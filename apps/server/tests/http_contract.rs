//! Run only in GitHub Actions. All database writes here are isolated fixtures,
//! not production server behavior. PostgreSQL requires TEST_POSTGRES_DSN.
use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use newapi_server::{AppState, MAX_BODY_BYTES, reload_loop, router};
use newapi_storage::Database;
use std::time::Duration;
use tower::ServiceExt;

const PATHS: [&str; 5] = [
    "/api/notice",
    "/api/about",
    "/api/home_page_content",
    "/api/user-agreement",
    "/api/privacy-policy",
];
const KEYS: [&str; 5] = [
    "Notice",
    "About",
    "HomePageContent",
    "legal.user_agreement",
    "legal.privacy_policy",
];

async fn sqlite_fixture() -> Database {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::query(r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#)
        .execute(&pool)
        .await
        .unwrap();
    Database::Sqlite(pool)
}

async fn set_value(db: &Database, key: &str, value: &str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                r#"INSERT INTO options ("key", "value") VALUES (?, ?)
                ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value""#,
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(
                r#"INSERT INTO options ("key", "value") VALUES ($1, $2)
                ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value""#,
            )
            .bind(key)
            .bind(value)
            .execute(pool)
            .await
            .unwrap();
        }
    }
}

async fn request(state: &AppState, method: Method, path: &str) -> (StatusCode, String) {
    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    assert!(response.headers().contains_key("x-request-id"));
    assert_eq!(response.headers()["content-type"], "application/json");
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn defaults_and_health_are_distinct_from_initialization() {
    let state = AppState::default();
    for path in PATHS {
        assert_eq!(
            request(&state, Method::GET, path).await,
            (
                StatusCode::OK,
                r#"{"success":true,"message":"","data":""}"#.into()
            )
        );
    }
    assert_eq!(
        request(&state, Method::GET, "/health/live").await.0,
        StatusCode::OK
    );
    assert_eq!(
        request(&state, Method::GET, "/health/ready").await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"success":false,"message":"not ready","data":""}"#.into()
        )
    );
    let db = sqlite_fixture().await;
    state.reload(&db).await.unwrap();
    assert_eq!(
        request(&state, Method::GET, "/health/ready").await.0,
        StatusCode::OK
    );
    state.mark_not_ready();
    assert_eq!(
        request(&state, Method::GET, "/health/ready").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    db.close().await;
}

async fn assert_database_contract(db: Database) {
    let state = AppState::initialize(&db).await.unwrap();
    let values = [
        "  公告 Unicode  ",
        "# About\n保留空白",
        "<p>首页</p>",
        "https://example.test/agreement",
        "隐私\"条款\"\\原文",
    ];
    let expected_json_data = [
        "  公告 Unicode  ",
        "# About\\n保留空白",
        "<p>首页</p>",
        "https://example.test/agreement",
        "隐私\\\"条款\\\"\\\\原文",
    ];
    for (key, value) in KEYS.into_iter().zip(values) {
        set_value(&db, key, value).await;
    }
    // A database update cannot affect GET until the whole snapshot is loaded.
    assert_eq!(
        request(&state, Method::GET, PATHS[0]).await.1,
        r#"{"success":true,"message":"","data":""}"#
    );
    state.reload(&db).await.unwrap();
    for (path, expected) in PATHS.into_iter().zip(expected_json_data) {
        assert_eq!(
            request(&state, Method::GET, path).await,
            (
                StatusCode::OK,
                format!(r#"{{"success":true,"message":"","data":"{expected}"}}"#)
            )
        );
    }
    // Runtime database failure preserves all five fields, but withdraws readiness.
    db.close().await;
    assert!(state.reload(&db).await.is_err());
    assert!(!state.is_ready());
    for (path, expected) in PATHS.into_iter().zip(expected_json_data) {
        assert_eq!(
            request(&state, Method::GET, path).await,
            (
                StatusCode::OK,
                format!(r#"{{"success":true,"message":"","data":"{expected}"}}"#)
            )
        );
    }
    assert_eq!(
        request(&state, Method::GET, "/health/ready").await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        request(&state, Method::GET, "/health/live").await.0,
        StatusCode::OK
    );
    assert!(AppState::initialize(&db).await.is_err());
}

#[tokio::test]
async fn sqlite_public_config_contract() {
    assert_database_contract(sqlite_fixture().await).await;
}

#[tokio::test]
async fn postgres_public_config_contract() {
    // Intentionally no skip: CI must provision its isolated PostgreSQL service.
    let dsn = std::env::var("TEST_POSTGRES_DSN")
        .expect("Actions must provide TEST_POSTGRES_DSN for the PostgreSQL contract");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&dsn)
        .await
        .unwrap_or_else(|_| panic!("PostgreSQL fixture connection failed"));
    // Connection-local temporary table cannot alter an existing public.options.
    sqlx::query(r#"CREATE TEMPORARY TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#)
        .execute(&pool)
        .await
        .unwrap();
    assert_database_contract(Database::Postgres(pool)).await;
}

#[tokio::test]
async fn failed_initial_schema_load_and_recovery() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let missing_schema = Database::Sqlite(pool);
    assert!(AppState::initialize(&missing_schema).await.is_err());
    missing_schema.close().await;

    let db = sqlite_fixture().await;
    set_value(&db, "Notice", "last good value").await;
    let state = AppState::initialize(&db).await.unwrap();
    db.close().await;
    assert!(state.reload(&db).await.is_err());
    let recovered = sqlite_fixture().await;
    set_value(&recovered, "About", "recovered").await;
    state.reload(&recovered).await.unwrap();
    assert!(state.is_ready());
    // Missing Notice in the recovered database retains the previous value.
    assert_eq!(state.snapshot().notice, "last good value");
    assert_eq!(state.snapshot().about, "recovered");
    recovered.close().await;
}

#[tokio::test]
async fn paths_methods_and_queries_have_explicit_axum_behavior() {
    let state = AppState::default();
    for path in ["/", "/api", "/api/", "/api/status", "/unknown", "/api/notice/"] {
        assert_eq!(
            request(&state, Method::GET, path).await,
            (
                StatusCode::NOT_FOUND,
                r#"{"success":false,"message":"not found","data":""}"#.into()
            )
        );
    }
    for path in PATHS {
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS] {
            assert_eq!(
                request(&state, method, path).await,
                (
                    StatusCode::METHOD_NOT_ALLOWED,
                    r#"{"success":false,"message":"method not allowed","data":""}"#.into()
                )
            );
        }
        let (status, body) = request(&state, Method::HEAD, path).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_empty());
    }
    assert_eq!(
        request(&state, Method::GET, "/api/notice?token=private").await.1,
        r#"{"success":true,"message":"","data":""}"#
    );
}

#[tokio::test]
async fn body_limit_applies_without_content_length_and_ids_are_server_generated() {
    let app = router(AppState::default());
    let mut previous_id = None;
    for (size, expected) in [
        (MAX_BODY_BYTES, StatusCode::OK),
        (MAX_BODY_BYTES + 1, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/notice?credential=secret")
                    .header("x-request-id", "untrusted-secret")
                    .header("authorization", "Bearer private")
                    .body(Body::from(vec![b'x'; size]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let id = response.headers()["x-request-id"]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(id.starts_with("p1-"));
        assert_ne!(previous_id.as_ref(), Some(&id));
        previous_id = Some(id);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains("secret"));
        assert!(!body.contains("private"));
    }
}

#[tokio::test]
async fn reload_worker_publishes_updates_and_detects_failure() {
    let db = sqlite_fixture().await;
    let state = AppState::initialize(&db).await.unwrap();
    set_value(&db, "Notice", "periodic update").await;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(reload_loop(
        state.clone(),
        db.clone(),
        Duration::from_millis(10),
        rx,
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.snapshot().notice != "periodic update" {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    db.close().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.is_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.snapshot().notice, "periodic update");
    // Dropping every sender must stop the worker as well as sending true.
    drop(tx);
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn reload_worker_stops_and_withdraws_readiness() {
    let db = sqlite_fixture().await;
    let state = AppState::initialize(&db).await.unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    let worker = tokio::spawn(reload_loop(
        state.clone(),
        db.clone(),
        Duration::from_secs(3600),
        rx,
    ));
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(!state.is_ready());
    db.close().await;
}
