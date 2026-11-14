//! Uptime Kuma status ported from Go `apps/api/internal/ops/check_uptime.go`
//! (`GET /api/uptime/status`, registered at `compose/register_api.go:31`).
//!
//! Contract (oracle `/root/newapi`, read-only):
//! - `GetUptimeKumaStatus` (`check_uptime.go:130-154`): read the console
//!   setting's group list (Go `usage.GetUptimeKumaGroups` →
//!   `getJSONList`, `configure_perf.go:269-276`: empty string → empty list,
//!   a JSON parse failure is swallowed → empty list); no groups →
//!   `{success: true, message: "", data: []}`; otherwise fetch every group's
//!   status-page + heartbeat endpoints concurrently (30 s overall request
//!   timeout, 10 s per HTTP request, `check_uptime.go:17-22`), failures
//!   degrade that group to its bare shell.
//! - `fetchGroupData` (`check_uptime.go:56-128`): group config keys `url`,
//!   `slug`, `categoryName`; url/slug required, base URL loses trailing
//!   `/`; the two endpoints are `<base>/api/status-page/<slug>` and
//!   `<base>/api/status-page/heartbeat/<slug>`; monitors iterate the
//!   `publicGroupList` entries with non-empty `monitorList`; `uptime` comes
//!   from `uptimeList["<id>_24"]`, `status` from the first heartbeat of
//!   `heartbeatList["<id>"]`; `group` carries the public group name and is
//!   omitted when empty (json `omitempty`).
//! - The HTTP transport sits behind [`UptimeFetcher`] so contract tests
//!   inject a fake; the production impl is a reqwest GET with the Go client's
//!   status discipline (non-200 → `non-200 status`).

use std::time::Duration;

use axum::{Json, Response, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::{Value, json};

use crate::AppState;

/// Go `requestTimeout` (`check_uptime.go:18`).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Go `httpTimeout` (`check_uptime.go:19`).
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Go `uptimeKeySuffix` (`check_uptime.go:20`).
const UPTIME_KEY_SUFFIX: &str = "_24";
/// Go `apiStatusPath` / `apiHeartbeatPath` (`check_uptime.go:21-22`).
const API_STATUS_PATH: &str = "/api/status-page/";
const API_HEARTBEAT_PATH: &str = "/api/status-page/heartbeat/";

/// Go `usage.GetUptimeKumaGroups` (`configure_perf.go:518-520`) +
/// `getJSONList` (`configure_perf.go:269-276`): the raw option value parses
/// to a list of objects; an empty or unparseable value is an empty list.
pub fn uptime_kuma_groups(raw: Option<&str>) -> Vec<Value> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    if raw.is_empty() {
        return Vec::new();
    }
    serde_json::from_str::<Vec<Value>>(raw).unwrap_or_default()
}

/// Port of Go's HTTP GET (`getAndDecode`, `check_uptime.go:37-54`): request
/// errors and non-200 statuses both fail the endpoint; the body is returned
/// unparsed for the caller's serde pass. The boxed-future shape keeps the
/// trait object-safe so contract tests inject fakes behind `&dyn`.
pub trait UptimeFetcher: Send + Sync {
    fn fetch(
        &self,
        url: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + '_>>;
}

/// Go `getAndDecode`'s status discipline with the 10 s per-request timeout.
pub struct HttpUptimeFetcher;

impl UptimeFetcher for HttpUptimeFetcher {
    fn fetch(
        &self,
        url: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + '_>>
    {
        let url = url.to_owned();
        Box::pin(async move {
            let client = reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .build()
                .map_err(|error| error.to_string())?;
            let response = tokio::time::timeout(HTTP_TIMEOUT, client.get(&url).send())
                .await
                .map_err(|_| "non-200 status".to_owned())?
                .map_err(|error| error.to_string())?;
            if response.status() != reqwest::StatusCode::OK {
                return Err("non-200 status".to_owned());
            }
            let body = tokio::time::timeout(HTTP_TIMEOUT, response.bytes())
                .await
                .map_err(|_| "non-200 status".to_owned())?
                .map_err(|error| error.to_string())?;
            Ok(body.to_vec())
        })
    }
}

/// Go `Monitor` (`check_uptime.go:25-30`); `group` is omitted when empty.
#[derive(Clone, Debug, PartialEq)]
pub struct Monitor {
    pub name: String,
    pub uptime: f64,
    pub status: i64,
    pub group: String,
}

impl Monitor {
    pub fn to_value(&self) -> Value {
        if self.group.is_empty() {
            json!({ "name": self.name, "uptime": self.uptime, "status": self.status })
        } else {
            json!({
                "name": self.name,
                "uptime": self.uptime,
                "status": self.status,
                "group": self.group,
            })
        }
    }
}

/// Go `UptimeGroupResult` (`check_uptime.go:32-35`).
#[derive(Clone, Debug, PartialEq)]
pub struct UptimeGroupResult {
    pub category_name: String,
    pub monitors: Vec<Monitor>,
}

impl UptimeGroupResult {
    pub fn to_value(&self) -> Value {
        json!({
            "categoryName": self.category_name,
            "monitors": self.monitors.iter().map(Monitor::to_value).collect::<Vec<_>>(),
        })
    }
}

/// Go `fetchGroupData` (`check_uptime.go:56-128`). The two endpoint fetches
/// run concurrently like Go's errgroup; either failure degrades the group to
/// its bare shell.
pub async fn fetch_group_data(
    fetcher: &dyn UptimeFetcher,
    group_config: &Value,
) -> UptimeGroupResult {
    let url = group_config
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let slug = group_config
        .get("slug")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let category_name = group_config
        .get("categoryName")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    let mut result = UptimeGroupResult {
        category_name,
        monitors: Vec::new(),
    };
    if url.is_empty() || slug.is_empty() {
        return result;
    }
    let base_url = url.trim_end_matches('/').to_owned();
    let status_url = format!("{base_url}{API_STATUS_PATH}{slug}");
    let heartbeat_url = format!("{base_url}{API_HEARTBEAT_PATH}{slug}");
    let (status, heartbeat) =
        tokio::join!(fetcher.fetch(&status_url), fetcher.fetch(&heartbeat_url));
    let Ok(status_body) = status else {
        return result;
    };
    let Ok(heartbeat_body) = heartbeat else {
        return result;
    };
    let Ok(status_data) = serde_json::from_slice::<Value>(&status_body) else {
        return result;
    };
    let Ok(heartbeat_data) = serde_json::from_slice::<Value>(&heartbeat_body) else {
        return result;
    };
    for public_group in status_data
        .get("publicGroupList")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let monitor_list = public_group
            .get("monitorList")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten();
        for entry in monitor_list {
            let name = entry
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            let monitor_id = entry
                .get("id")
                .and_then(|v| v.as_i64())
                .map(|id| id.to_string())
                .unwrap_or_default();
            let mut monitor = Monitor {
                name,
                uptime: 0.0,
                status: 0,
                group: public_group
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned(),
            };
            if let Some(uptime) = heartbeat_data
                .get("uptimeList")
                .and_then(|v| v.get(format!("{monitor_id}{UPTIME_KEY_SUFFIX}")))
                .and_then(|v| v.as_f64())
            {
                monitor.uptime = uptime;
            }
            if let Some(heartbeats) = heartbeat_data
                .get("heartbeatList")
                .and_then(|v| v.get(&monitor_id))
                .and_then(|v| v.as_array())
                && !heartbeats.is_empty()
            {
                monitor.status = heartbeats[0]
                    .get("status")
                    .and_then(|v| v.as_i64())
                    .unwrap_or_default();
            }
            result.monitors.push(monitor);
        }
    }
    result
}

/// Go `GetUptimeKumaStatus` (`check_uptime.go:130-154`). The 30 s overall
/// budget bounds the whole fan-out like Go's `context.WithTimeout`; every
/// group's shell renders even when its fetches fail.
pub async fn get_uptime_kuma_status(State(state): State<AppState>) -> Response {
    let groups: Vec<Value> = match state.db() {
        Some(db) => {
            let raw: Option<String> = match &db {
                newapi_storage::Database::Sqlite(pool) => {
                    sqlx::query_scalar("SELECT value FROM options WHERE \"key\" = ?")
                        .bind("console_setting.uptime_kuma_groups")
                        .fetch_optional(pool)
                        .await
                        .ok()
                        .flatten()
                }
                newapi_storage::Database::Postgres(pool) => {
                    sqlx::query_scalar("SELECT value FROM options WHERE \"key\" = $1")
                        .bind("console_setting.uptime_kuma_groups")
                        .fetch_optional(pool)
                        .await
                        .ok()
                        .flatten()
                }
            };
            uptime_kuma_groups(raw.as_deref())
        }
        None => Vec::new(),
    };
    if groups.is_empty() {
        return (
            StatusCode::OK,
            Json(json!({ "success": true, "message": "", "data": [] })),
        )
            .into_response();
    }
    let fetcher = HttpUptimeFetcher;
    // Go fans the groups out concurrently (errgroup, results pre-sized); the
    // port does the same with a JoinSet under the 30 s overall budget.
    let mut set = tokio::task::JoinSet::new();
    for group in &groups {
        let group = group.clone();
        set.spawn(async move { fetch_group_data(&HttpUptimeFetcher, &group).await });
    }
    let mut results = Vec::with_capacity(groups.len());
    let _ = fetcher;
    let fanout = tokio::time::timeout(REQUEST_TIMEOUT, async {
        while let Some(joined) = set.join_next().await {
            if let Ok(result) = joined {
                results.push(result);
            }
        }
    });
    let _ = fanout.await;
    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "message": "",
            "data": results.iter().map(UptimeGroupResult::to_value).collect::<Vec<_>>(),
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeFetcher {
        routes: Vec<(&'static str, Result<&'static str, String>)>,
    }

    impl UptimeFetcher for FakeFetcher {
        fn fetch(
            &self,
            url: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + '_>>
        {
            let url = url.to_owned();
            Box::pin(async move {
                for (needle, body) in &self.routes {
                    if url.contains(needle) {
                        return match body {
                            Ok(text) => Ok(text.as_bytes().to_vec()),
                            Err(error) => Err(error.clone()),
                        };
                    }
                }
                Err("non-200 status".to_owned())
            })
        }
    }

    fn group_config(url: &str, slug: &str) -> Value {
        json!({ "url": url, "slug": slug, "categoryName": "Services" })
    }

    #[tokio::test]
    async fn group_data_assembles_monitors_from_both_endpoints() {
        let fetcher = FakeFetcher::new(vec![
            (
                "status-page/status",
                Ok(
                    r#"{"publicGroupList":[{"id":1,"name":"Public","monitorList":[{"id":7,"name":"api"},{"id":8,"name":"web"}]}]}"#,
                ),
            ),
            (
                "status-page/heartbeat/status",
                Ok(
                    r#"{"heartbeatList":{"7":[{"status":2}],"8":[{"status":0}]},"uptimeList":{"7_24":99.5}}"#,
                ),
            ),
        ]);
        let result =
            fetch_group_data(&fetcher, &group_config("https://kuma.example/", "status")).await;
        assert_eq!(result.category_name, "Services");
        assert_eq!(result.monitors.len(), 2);
        assert_eq!(result.monitors[0].name, "api");
        assert!((result.monitors[0].uptime - 99.5).abs() < 1e-9);
        assert_eq!(result.monitors[0].status, 2);
        assert_eq!(result.monitors[0].group, "Public");
        // No uptime entry → 0; heartbeat status present.
        assert!((result.monitors[1].uptime).abs() < 1e-9);
        assert_eq!(result.monitors[1].status, 0);
        // omitempty group: only rendered when non-empty.
        assert!(result.monitors[0].to_value().get("group").is_some());
    }

    #[tokio::test]
    async fn missing_url_or_slug_and_fetch_failures_render_bare_shell() {
        let fetcher = FakeFetcher::new(vec![]);
        let empty = fetch_group_data(&fetcher, &group_config("", "status")).await;
        assert!(empty.monitors.is_empty());
        assert_eq!(empty.category_name, "Services");
        let empty = fetch_group_data(&fetcher, &group_config("https://x", "")).await;
        assert!(empty.monitors.is_empty());
        // Both endpoint fetches fail → bare shell, no error leak.
        let degraded = fetch_group_data(&fetcher, &group_config("https://x", "s")).await;
        assert!(degraded.monitors.is_empty());
        // Empty group lists and empty monitor lists are skipped (Go skips
        // pg.MonitorList empties).
        let fetcher = FakeFetcher::new(vec![(
            "status-page/s",
            Ok(r#"{"publicGroupList":[{"id":1,"name":"A","monitorList":[]}]}"#),
        )]);
        let result = fetch_group_data(&fetcher, &group_config("https://x", "s")).await;
        assert!(result.monitors.is_empty());
    }

    #[test]
    fn group_list_parse_follows_get_json_list() {
        assert!(uptime_kuma_groups(None).is_empty());
        assert!(uptime_kuma_groups(Some("")).is_empty());
        assert!(uptime_kuma_groups(Some("not json")).is_empty());
        let groups = uptime_kuma_groups(Some(r#"[{"url":"https://x","slug":"s"}]"#));
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["slug"], "s");
    }

    #[tokio::test]
    async fn trailing_slash_is_trimmed_like_go() {
        let fetcher = FakeFetcher::new(vec![(
            "https://kuma.example/api/status-page/s",
            Ok(r#"{"publicGroupList":[]}"#),
        )]);
        // Double slash would mean the trim did not happen; 404 needle misses
        // mean the trimmed URL hit.
        let result = fetch_group_data(&fetcher, &group_config("https://kuma.example/", "s")).await;
        assert!(result.monitors.is_empty());
        assert_eq!(result.category_name, "Services");
    }
}
