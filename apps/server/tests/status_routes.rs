//! HTTP contracts for `GET /api/status`.
//!
//! Router wiring is owned by the mainline integrator (parallel agents work on
//! `http.rs`), so the route is not registered yet. These integration tests
//! therefore exercise the public builder `newapi_server::status::status_body`
//! against `AppState::default()` — the same entry point the handler wraps. The
//! exhaustive per-field ledger (every honest default, AuthSettings/PublicConfig
//! pass-through, conditional injection) lives in `#[cfg(test)] mod tests` in
//! `src/status.rs`, where snapshot injection is reachable.
//!
//! After the mainline registers `get(crate::status::handle)` on `/api/status`,
//! enable the router-level test below and keep it aligned with
//! `session_routes.rs` (tower `oneshot` over the production router).

use newapi_server::{AppState, status::status_body};
use serde_json::Value;

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

// TODO(mainline wiring): enable once `/api/status` is registered in the
// production router. Shape:
//
// #[tokio::test]
// async fn status_route_serves_the_envelope_over_http() {
//     let response = newapi_server::router(AppState::default())
//         .oneshot(
//             Request::builder()
//                 .method(Method::GET)
//                 .uri("/api/status")
//                 .body(Body::empty())
//                 .unwrap(),
//         )
//         .await
//         .unwrap();
//     assert_eq!(response.status(), StatusCode::OK);
//     assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
//     let body: Value =
//         serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
//             .unwrap();
//     assert_eq!(body["success"], Value::Bool(true));
//     assert_eq!(body["message"], "");
//     assert_eq!(body["data"]["theme"], "default");
// }
