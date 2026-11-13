//! 网关 outbox Redis 发布器的双后端契约（SQLite 内存 + 独立 PG schema），
//! Redis 面用 trait 替身（对齐 Go `publish_gateway_config.go` 的行为契约）：
//!
//! - 待发布批次按 revision 升序逐条发布，载荷 `{"routing_revision": N}`、
//!   channel `new-api:gateway:routing-revision:v1`。
//! - 成功：先记 `published` 尝试、再盖 `published_at`（行离开 pending 集）。
//! - 失败：记分类（redis_disabled / redis_unavailable），行留在 pending，
//!   下轮重试。
//! - `revision <= 0` 是 invalid：不触达 publisher。
//! - 存储侧 `ListPendingGatewayConfigOutbox` 的 limit/排序由既有契约测试覆盖。

use std::sync::{Arc, Mutex};

use newapi_catalog::gateway_revision::{
    initialize_gateway_config_revision, list_pending_gateway_config_outbox,
};
use newapi_catalog::outbox_publisher::{
    GATEWAY_ROUTING_REVISION_CHANNEL, OutboxPublishError, RevisionPublishFailure,
    RoutingRevisionPublisher, classify_publish_failure, publish_gateway_routing_revision,
    publish_pending_gateway_revisions, run_gateway_config_outbox_publisher,
};
use newapi_storage::Database;
use sqlx::{
    ConnectOptions, Executor,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::str::FromStr;

const REVISION_SQLITE: &str = "CREATE TABLE gateway_config_revisions (id BIGINT PRIMARY KEY, routing_revision BIGINT NOT NULL)";
const REVISION_POSTGRES: &str = "CREATE TABLE gateway_config_revisions (id BIGINT PRIMARY KEY, routing_revision BIGINT NOT NULL)";

const OUTBOX_SQLITE: &str = r#"CREATE TABLE gateway_config_outboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    routing_revision BIGINT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP,
    publish_attempts INTEGER NOT NULL DEFAULT 0,
    last_publish_error_class VARCHAR(64)
)"#;

const OUTBOX_POSTGRES: &str = r#"CREATE TABLE gateway_config_outboxes (
    id BIGSERIAL PRIMARY KEY,
    routing_revision BIGINT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP,
    publish_attempts INTEGER NOT NULL DEFAULT 0,
    last_publish_error_class VARCHAR(64)
)"#;

#[derive(Default)]
struct CapturedCall {
    channel: String,
    payload: String,
}

/// 可编程替身：按 revision 决定成功/失败类别，记录全部调用。
struct FakePublisher {
    calls: Mutex<Vec<CapturedCall>>,
    /// 恒失败时的类别；None = 恒成功。
    failure: Option<RevisionPublishFailure>,
}

impl FakePublisher {
    fn ok() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            failure: None,
        })
    }
    fn failing(failure: RevisionPublishFailure) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            failure: Some(failure),
        })
    }
    fn captured(&self) -> Vec<(String, i64)> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| {
                let payload: serde_json::Value = serde_json::from_str(&call.payload).unwrap();
                (
                    call.channel.clone(),
                    payload["routing_revision"].as_i64().unwrap(),
                )
            })
            .collect()
    }
}

impl RoutingRevisionPublisher for FakePublisher {
    fn publish(
        &self,
        channel: &str,
        payload: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), RevisionPublishFailure>> + Send + '_>>
    {
        self.calls.lock().unwrap().push(CapturedCall {
            channel: channel.to_owned(),
            payload: payload.to_owned(),
        });
        let result = match &self.failure {
            None => Ok(()),
            Some(failure) => match failure {
                RevisionPublishFailure::Disabled => Err(RevisionPublishFailure::Disabled),
                RevisionPublishFailure::Unavailable => Err(RevisionPublishFailure::Unavailable),
            },
        };
        Box::pin(async move { result })
    }
}

async fn execute(db: &Database, statement: &'static str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(statement).execute(pool).await.unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(statement).execute(pool).await.unwrap();
        }
    }
}

async fn create_schema(db: &Database) {
    match db {
        Database::Sqlite(_) => {
            execute(db, REVISION_SQLITE).await;
            execute(db, OUTBOX_SQLITE).await;
        }
        Database::Postgres(_) => {
            execute(db, REVISION_POSTGRES).await;
            execute(db, OUTBOX_POSTGRES).await;
        }
    }
    initialize_gateway_config_revision(db).await.unwrap();
}

/// 种三条待发布 outbox（乱序插入，验证 revision 升序发布）。
async fn seed_outbox(db: &Database, revisions: &[i64]) {
    for revision in revisions {
        match db {
            Database::Sqlite(pool) => {
                sqlx::query("INSERT INTO gateway_config_outboxes (routing_revision) VALUES (?)")
                    .bind(revision)
                    .execute(pool)
                    .await
                    .unwrap();
            }
            Database::Postgres(pool) => {
                sqlx::query("INSERT INTO gateway_config_outboxes (routing_revision) VALUES ($1)")
                    .bind(revision)
                    .execute(pool)
                    .await
                    .unwrap();
            }
        }
    }
}

async fn outbox_rows(db: &Database) -> Vec<(i64, i64, Option<String>)> {
    match db {
        Database::Sqlite(pool) => sqlx::query_as(
            "SELECT id, routing_revision, last_publish_error_class \
             FROM gateway_config_outboxes ORDER BY routing_revision ASC",
        )
        .fetch_all(pool)
        .await
        .unwrap(),
        Database::Postgres(pool) => sqlx::query_as(
            "SELECT id, routing_revision, last_publish_error_class \
             FROM gateway_config_outboxes ORDER BY routing_revision ASC",
        )
        .fetch_all(pool)
        .await
        .unwrap(),
    }
}

async fn pending_revisions(db: &Database) -> Vec<i64> {
    list_pending_gateway_config_outbox(db, 100)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.routing_revision)
        .collect()
}

async fn postgres_db() -> Option<Database> {
    let dsn = std::env::var("TEST_POSTGRES_DSN").ok()?;
    let options: sqlx::postgres::PgConnectOptions = dsn.parse().unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone().disable_statement_logging())
        .await
        .unwrap();
    let schema = format!("outbox_pub_{}", std::process::id());
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .unwrap();
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .idle_timeout(None)
        .max_lifetime(None)
        .after_connect(move |connection, _| {
            let path = search_path.clone();
            Box::pin(async move {
                connection
                    .execute(&*format!("SET search_path = \"{path}\""))
                    .await?;
                Ok(())
            })
        })
        .connect_with(options.disable_statement_logging())
        .await
        .unwrap();
    Some(Database::Postgres(pool))
}

async fn both_backends() -> Vec<Database> {
    let mut backends = Vec::new();
    let options = SqliteConnectOptions::from_str("sqlite::memory:")
        .unwrap()
        .disable_statement_logging();
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .unwrap();
    backends.push(Database::Sqlite(pool));
    if let Some(pg) = postgres_db().await {
        backends.push(pg);
    }
    backends
}

#[tokio::test]
async fn publishes_pending_batch_in_order_and_marks_published() {
    for db in both_backends().await {
        create_schema(&db).await;
        seed_outbox(&db, &[7, 3, 5]).await;

        let publisher = FakePublisher::ok();
        publish_pending_gateway_revisions(&db, publisher.as_ref(), 100)
            .await
            .unwrap();

        let calls = publisher.captured();
        assert_eq!(calls.len(), 3);
        for (index, (channel, revision)) in calls.iter().enumerate() {
            assert_eq!(channel, GATEWAY_ROUTING_REVISION_CHANNEL);
            assert_eq!(*revision, [3, 5, 7][index]);
        }
        // 全部标记 published：离开 pending 集，尝试类别为 published。
        assert!(pending_revisions(&db).await.is_empty());
        for (id, _, error_class) in outbox_rows(&db).await {
            assert_eq!(error_class.as_deref(), Some("published"), "row {id}");
            assert!(id > 0);
        }
        // 已发布的不再重发。
        publish_pending_gateway_revisions(&db, publisher.as_ref(), 100)
            .await
            .unwrap();
        assert_eq!(publisher.captured().len(), 3);
    }
}

#[tokio::test]
async fn publish_failure_records_class_and_keeps_row_pending() {
    for db in both_backends().await {
        create_schema(&db).await;
        seed_outbox(&db, &[4, 9]).await;

        let publisher = FakePublisher::failing(RevisionPublishFailure::Unavailable);
        publish_pending_gateway_revisions(&db, publisher.as_ref(), 100)
            .await
            .unwrap();
        assert_eq!(publisher.captured().len(), 2);
        let rows = outbox_rows(&db).await;
        assert!(
            rows.iter()
                .all(|(_, _, class)| class.as_deref() == Some("redis_unavailable"))
        );
        assert_eq!(pending_revisions(&db).await, vec![4, 9]);

        // 恢复后重试成功。
        let publisher = FakePublisher::ok();
        publish_pending_gateway_revisions(&db, publisher.as_ref(), 100)
            .await
            .unwrap();
        assert!(pending_revisions(&db).await.is_empty());

        // Disabled 分类的类别名。
        assert_eq!(
            classify_publish_failure(&OutboxPublishError::Disabled),
            "redis_disabled"
        );
    }
}

#[tokio::test]
async fn non_positive_revision_is_invalid_without_publish() {
    let publisher = FakePublisher::ok();
    for revision in [0i64, -1] {
        match publish_gateway_routing_revision(publisher.as_ref(), revision).await {
            Err(OutboxPublishError::InvalidRevision(value)) => assert_eq!(value, revision),
            other => panic!("expected invalid revision, got {other:?}"),
        }
    }
    assert!(publisher.captured().is_empty());
}

#[tokio::test]
async fn publisher_loop_publishes_and_exits_on_shutdown() {
    for db in both_backends().await {
        create_schema(&db).await;
        seed_outbox(&db, &[2]).await;

        let publisher = FakePublisher::ok();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let db_for_task = db.clone();
        let publisher_for_task: Arc<dyn RoutingRevisionPublisher> = publisher.clone();
        let loop_task = tokio::spawn(async move {
            run_gateway_config_outbox_publisher(
                &db_for_task,
                &*publisher_for_task,
                1,
                async move {
                    let _ = shutdown_rx.await;
                },
            )
            .await;
        });
        // 等待首轮发布落地（每轮先发布再等待）。
        for _ in 0..200 {
            if !pending_revisions(&db).await.is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            } else {
                break;
            }
        }
        assert!(pending_revisions(&db).await.is_empty());
        shutdown_tx.send(()).unwrap();
        loop_task.await.unwrap();
        // 退出后不再发布。
        let calls_after = publisher.captured().len();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(publisher.captured().len(), calls_after);
    }
}
