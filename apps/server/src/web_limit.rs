//! Go `GlobalWebRateLimit`（mark "GW"）的 Axum 移植。Go 的 web 路由
//! （`register_web.go:13-17` 的 `SetWebRouter`）在所有业务路由之后注册于引擎
//! 根部：`Use(GlobalWebRateLimit)` 只覆盖其后注册的静态资源与 `NoRoute` 兜底
//! 链，`/api` 等业务路由组（各自注册在前）不经 GW。本端口尚无静态资源，
//! GW 表面即“未匹配业务路由的兜底表面”：除 `/api`、`/health/live`、
//! `/health/ready` 之外的路径（含未匹配的 `/`、`/v1/...`、`/assets/...` 等）
//! 任意方法都走 GW，对应 Go 的 `NoRoute` 语义（gin 的
//! `HandleMethodNotAllowed=false` 使错方法请求同样落入兜底链）。
//!
//! 与 `global_limit`（GA）的两点已记录差异：
//! - Go 的 `NoRoute` 链含 GW 不含 GA，因此 Go 里 `/api/unknown` 只受 GW 约束；
//!   本端口 GA 中间件已先行覆盖全部 `/api` 路径（含未匹配），为避免同一请求
//!   被双重限流，GW 表面排除 `/api`，`/api/unknown` 保持 GA 单独约束。
//! - `/health/*` 是 Rust 的 P1 健康端点，Go 无对应路由；不纳入 GW 表面，
//!   以免部署探活与 P1 校验触发 Web 限流。
//!
//! 键推导（`GW` + `ClientIP`）、429 裸状态码 + `Retry-After`、Redis 故障的 500
//! 与 GA 完全一致（Go `limit_rate.go:109-145`：拒绝时空 body、位于 Cache
//! 之前，故无缓存头）。

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::AppState;

/// GW 表面：`/api`（含子路径）与 P1 健康端点之外的全部路径。与
/// `global_limit::is_api_path` 互补，两者须同步修改。
fn is_web_surface(path: &str) -> bool {
    !(path == "/api"
        || path.starts_with("/api/")
        || path == "/health/live"
        || path == "/health/ready")
}

/// 全局 Web 限流中间件；`enable=false` 或测试未注入限流器时直通且不记录
/// 任何状态（`RateLimiter::check` 内部短路，与 Go 的 `defNext` 一致）。
pub(crate) async fn global_web_rate_limit(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if !is_web_surface(request.uri().path()) {
        return next.run(request).await;
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let ip = crate::http::request_ip(&state, request.headers(), peer);
    let now = crate::http::now_seconds();
    // Go `mark` 为 "GW"：内存键是 mark + ClientIP，Redis 键另由 limiter 组装。
    match state.check_global_web_rate_limit(&ip, now).await {
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
        // Go 的 Redis 故障分支：500 + Abort，位于 Cache 之前。
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    next.run(request).await
}
