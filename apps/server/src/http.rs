use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;

use crate::AppState;

pub const MAX_BODY_BYTES: usize = 64 * 1024;
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Serialize)]
struct Envelope {
    success: bool,
    message: &'static str,
    data: String,
}

fn success(data: String) -> Response {
    Json(Envelope {
        success: true,
        message: "",
        data,
    })
    .into_response()
}

fn failure(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        Json(Envelope {
            success: false,
            message,
            data: String::new(),
        }),
    )
        .into_response()
}

/// Axum GET includes implicit HEAD. Other methods get JSON 405, unknown paths
/// JSON 404, including /api and trailing slashes. These are explicit P1 choices,
/// not claims of equivalence with the unmeasured Go/Fiber middleware chain.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/notice", get(notice))
        .route("/api/about", get(about))
        .route("/api/home_page_content", get(home_page_content))
        .route("/api/user-agreement", get(user_agreement))
        .route("/api/privacy-policy", get(privacy_policy))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
        .layer(middleware::from_fn(boundary))
}

async fn notice(State(state): State<AppState>) -> Response {
    success(state.snapshot().notice)
}

async fn about(State(state): State<AppState>) -> Response {
    success(state.snapshot().about)
}

async fn home_page_content(State(state): State<AppState>) -> Response {
    success(state.snapshot().home_page_content)
}

async fn user_agreement(State(state): State<AppState>) -> Response {
    success(state.snapshot().user_agreement)
}

async fn privacy_policy(State(state): State<AppState>) -> Response {
    success(state.snapshot().privacy_policy)
}

async fn live() -> Response {
    success("live".into())
}

async fn ready(State(state): State<AppState>) -> Response {
    if state.is_ready() {
        success("ready".into())
    } else {
        failure(StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

async fn not_found() -> Response {
    failure(StatusCode::NOT_FOUND, "not found")
}

async fn method_not_allowed() -> Response {
    failure(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

/// Do not use the default TraceLayer span: it records the URI, including query
/// credentials. Never trust or log an incoming request-id/header/body either.
async fn boundary(request: Request, next: Next) -> Response {
    boundary_with_timeout(request, next, Duration::from_secs(30)).await
}

// 测试可注入短超时，无需等待生产环境的三十秒期限。
async fn boundary_with_timeout(request: Request, next: Next, timeout: Duration) -> Response {
    let is_head = request.method() == Method::HEAD;
    let id = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    // A Tokio task boundary catches unwinding handler panics without an extra
    // dependency. main installs a hook that never emits the panic payload.
    let mut task = tokio::spawn(async move {
        let (parts, body) = request.into_parts();
        // Read a bounded body even for GET and fallbacks: extractor-only limits
        // otherwise do not protect endpoints that never extract their body.
        match to_bytes(body, MAX_BODY_BYTES).await {
            Ok(bytes) => {
                next.run(Request::from_parts(parts, Body::from(bytes)))
                    .await
            }
            Err(_) => failure(StatusCode::PAYLOAD_TOO_LARGE, "request body rejected"),
        }
    });
    // Dropping the HTTP future (client disconnect) must not detach body reads.
    let _abort_on_drop = AbortOnDrop(task.abort_handle());
    let mut response = match tokio::time::timeout(timeout, &mut task).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => failure(StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
        Err(_) => {
            task.abort();
            let _ = task.await;
            failure(StatusCode::REQUEST_TIMEOUT, "request timed out")
        }
    };
    // 外层产生的错误不经过 Axum 的 HEAD 路由处理，必须在最终出口统一去体。
    // 保留原响应头和状态，不把 GET 表示长度改成零。
    if is_head {
        *response.body_mut() = Body::empty();
    }
    if let Ok(value) = HeaderValue::from_str(&format!("p1-{id}")) {
        response.headers_mut().insert("x-request-id", value);
    }
    tracing::info!(
        request_id = id,
        status = response.status().as_u16(),
        "request completed"
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    #[tokio::test]
    async fn head_boundary_errors_have_no_body() {
        async fn panic_handler() -> StatusCode {
            panic!("private panic payload")
        }
        async fn blocked_handler() -> StatusCode {
            std::future::pending().await
        }
        async fn short_boundary(request: Request, next: Next) -> Response {
            let timeout = if request.uri().path() == "/blocked" {
                Duration::from_millis(10)
            } else {
                Duration::from_secs(30)
            };
            boundary_with_timeout(request, next, timeout).await
        }
        let app = Router::new()
            .route("/ok", get(|| async { StatusCode::OK }))
            .route("/panic", get(panic_handler))
            .route("/blocked", get(blocked_handler))
            .layer(middleware::from_fn(short_boundary));
        for (path, size, expected) in [
            ("/ok", MAX_BODY_BYTES + 1, StatusCode::PAYLOAD_TOO_LARGE),
            ("/blocked", 0, StatusCode::REQUEST_TIMEOUT),
            ("/panic", 0, StatusCode::INTERNAL_SERVER_ERROR),
        ] {
            for method in [Method::GET, Method::HEAD] {
                let is_head = method == Method::HEAD;
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(path)
                            .body(Body::from(vec![b'x'; size]))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), expected);
                assert_eq!(response.headers()["content-type"], "application/json");
                assert!(response.headers().contains_key("x-request-id"));
                let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
                assert_eq!(bytes.is_empty(), is_head);
                assert!(!String::from_utf8_lossy(&bytes).contains("private panic payload"));
            }
        }
    }

    #[tokio::test]
    async fn panic_returns_sanitized_json_and_request_id() {
        async fn panic_handler() -> StatusCode {
            panic!("private panic payload")
        }
        let app = Router::new()
            .route("/panic", get(panic_handler))
            .layer(middleware::from_fn(boundary));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/panic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(response.headers().contains_key("x-request-id"));
        let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
        assert_eq!(
            bytes.as_ref(),
            br#"{"success":false,"message":"internal server error","data":""}"#
        );
    }
}
