//! Go `GlobalAPIRateLimit`（mark "GA"）的 Axum 移植：`/api` 路由组前的全局
//! IP 限流。后端与 `CriticalRateLimit` 共用 `RateLimiter`（内存滑动窗口 /
//! Redis 固定窗口），键推导 `GA` + ClientIP 与 Go 的
//! `rateLimit:v2:ip:GA:<ip>` 一致。
//!
//! 挂载位置复刻 Go 的注册顺序：`apiRouter.Use(GlobalAPIRateLimit)` 位于所有
//! 路由级中间件之前，因此 GA 先于 `login_guard`/`session_mutation_guard` 的
//! CT 限流执行。429 与 Redis 故障的 500 都产生于 `DisableCache` 之前，是裸
//! 状态码（无 no-cache 头、无 JSON 体），与 Go 的 `c.Status` + `c.Abort` 一致。

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::AppState;

/// Go 的 `apiRouter` 分组前缀：`/api` 本身与任意 `/api/...` 子路径受 GA
/// 约束；`/health` 等非 API 路径直通（Go 的 `GlobalWebRateLimit` "GW" 不在
/// 本期范围）。
fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

/// 全局 API 限流中间件；`enable=false` 或测试未注入限流器时直通且不记录
/// 任何状态（`RateLimiter::check` 内部短路，与 Go 的 `defNext` 一致）。
pub(crate) async fn global_api_rate_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if !is_api_path(request.uri().path()) {
        return next.run(request).await;
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let ip = crate::http::request_ip(&state, request.headers(), peer);
    let now = crate::http::now_seconds();
    // Go `mark` 为 "GA"：内存键是 mark + ClientIP，Redis 键另由 limiter 组装。
    match state.check_global_api_rate_limit(&ip, now).await {
        Ok(None) => {}
        Ok(Some(retry_after)) => {
            let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
            if retry_after > 0
                && let Ok(value) = HeaderValue::from_str(&retry_after.to_string())
            {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            return response;
        }
        // Go 的 Redis 故障分支：500 + Abort，位于 DisableCache 之前。
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    next.run(request).await
}
