use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

use axum::{body::Body, http::Request};
use newapi_server::{AppState, database_error_class, router};
use tower::ServiceExt;

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn access_logs_do_not_record_uri_headers_or_body() {
    let buffer = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_env_filter("off,newapi_server=info")
        .with_writer(buffer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let response = router(AppState::default())
        .oneshot(
            Request::builder()
                .uri("/unknown-path-secret?token=query-secret")
                .header("authorization", "Bearer header-secret")
                .header("cookie", "session=cookie-secret")
                .header("x-request-id", "request-id-secret")
                .body(Body::from("body-secret"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    let output = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("request completed"));
    assert!(output.contains("request_id"));
    for secret in [
        "unknown-path-secret",
        "query-secret",
        "header-secret",
        "cookie-secret",
        "request-id-secret",
        "body-secret",
    ] {
        assert!(!output.contains(secret));
    }
}

#[test]
fn panic_hook_logs_only_fixed_classification() {
    let buffer = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_env_filter("off,newapi_server=info")
        .with_writer(buffer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    // 本集成测试进程内仅此用例修改 hook；恢复后再断言，避免影响其他用例。
    let previous = std::panic::take_hook();
    newapi_server::install_safe_panic_hook();
    let result = std::panic::catch_unwind(|| panic!("credential-panic-secret"));
    std::panic::set_hook(previous);
    assert!(result.is_err());
    let output = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("internal task failed"));
    assert!(!output.contains("credential-panic-secret"));
    assert!(!output.contains("log_redaction.rs"));
}

#[test]
fn database_error_class_never_formats_the_error_payload() {
    let error = sqlx::Error::Io(io::Error::other("postgres://user:dsn-secret@host/db"));
    assert_eq!(database_error_class(&error), "io");
    assert_eq!(
        database_error_class(&sqlx::Error::PoolClosed),
        "pool_closed"
    );
}
