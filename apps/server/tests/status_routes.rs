//! HTTP contracts for `GET /api/status`, served over the production router.
//!
//! The exhaustive per-field ledger (every honest default, AuthSettings/
//! PublicConfig pass-through, conditional injection) lives in
//! `#[cfg(test)] mod tests` in `src/status.rs`, where snapshot injection is
//! reachable. This file pins what only the real router can prove: the route is
//! registered, answers 200 with the Go envelope, and carries no DisableCache
//! headers (Go mounts no DisableCache on `/api/status`).

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use newapi_server::{AppState, router, status::status_body};
use serde_json::Value;
use tower::ServiceExt;

#[test]
fn default_state_status_body_keeps_the_go_envelope_contract() {
    let body = status_body(&AppState::default());
    let envelope = body.as_object().expect("envelope must be an object");
    assert_eq!(envelope.len(), 3);
    assert_eq!(envelope["success"], Value::Bool(true));
    assert_eq!(envelope["message"], Value::String(String::new()));
    let data = envelope["data"].as_object().expect("data must be an object");
    assert_eq!(data["theme"], "default");
    assert!(!data["version"].as_str().unwrap().is_empty());
    assert!(data["start_time"].as_i64().unwrap() > 0);
    // Go emits the key only when enabled custom providers exist; the port
    // never has a data source yet, so the key must stay absent.
    assert!(data.get("custom_oauth_providers").is_none());
}

#[tokio::test]
async fn status_route_serves_the_envelope_over_http() {
    let response = router(AppState::default())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    // Go 该路由不挂 DisableCache：响应不得携带 no-cache 三头。
    assert!(!response.headers().contains_key(header::CACHE_CONTROL));
    assert!(!response.headers().contains_key(header::PRAGMA));
    assert!(!response.headers().contains_key(header::EXPIRES));
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap()).unwrap();
    assert_eq!(body["success"], Value::Bool(true));
    assert_eq!(body["message"], "");
    assert_eq!(body["data"]["theme"], "default");
    assert_eq!(body["data"]["setup"], Value::Bool(false));
}

#[tokio::test]
async fn status_post_is_method_not_allowed() {
    let response = router(AppState::default())
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}
