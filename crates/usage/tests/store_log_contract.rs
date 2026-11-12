//! 日志写侧契约（双后端：内存 SQLite + 隔离 PostgreSQL schema）。
//!
//! Go oracle：`apps/api/internal/usage/store_log.go` 的写函数。核心契约：
//! 写入列集合与读取端 SELECT 白名单一致（`log_http.rs` 的 `LOG_COLUMNS`），
//! 写入后用同样的投影取回，逐列比对。PostgreSQL 测试在 `TEST_POSTGRES_DSN`
//! 缺席时跳过（仓库双后端契约的统一形态）。

use chrono::Utc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

use newapi_storage::Database;
use newapi_usage::store_log::{self, ConsumeLogContext, RecordConsumeLogParams, TopupAdminInfo};
use newapi_usage::usedata::{self, QuotaDataLogParams};
use serde_json::{Map, Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// usedata 的进程级缓存与 save/flush 语义在并发测试下会互相吞并条目，
/// 这些用例必须串行化。
static USEDATA_LOCK: Mutex<()> = Mutex::const_new(());

const SQLITE_LOGS: &str = r#"CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0,
    type INTEGER NOT NULL DEFAULT 0,
    content TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    token_name TEXT NOT NULL DEFAULT '',
    model_name TEXT NOT NULL DEFAULT '',
    quota BIGINT NOT NULL DEFAULT 0,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    use_time BIGINT NOT NULL DEFAULT 0,
    is_stream INTEGER NOT NULL DEFAULT 0,
    channel_id BIGINT NOT NULL DEFAULT 0,
    channel_name TEXT NOT NULL DEFAULT '',
    token_id BIGINT NOT NULL DEFAULT 0,
    "group" TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    upstream_request_id TEXT NOT NULL DEFAULT '',
    other TEXT NOT NULL DEFAULT ''
)"#;

const POSTGRES_LOGS: &str = r#"CREATE TABLE IF NOT EXISTS logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL DEFAULT 0,
    type BIGINT NOT NULL DEFAULT 0,
    content TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    token_name TEXT NOT NULL DEFAULT '',
    model_name TEXT NOT NULL DEFAULT '',
    quota BIGINT NOT NULL DEFAULT 0,
    prompt_tokens BIGINT NOT NULL DEFAULT 0,
    completion_tokens BIGINT NOT NULL DEFAULT 0,
    use_time BIGINT NOT NULL DEFAULT 0,
    is_stream BOOLEAN NOT NULL DEFAULT FALSE,
    channel_id BIGINT NOT NULL DEFAULT 0,
    channel_name TEXT NOT NULL DEFAULT '',
    token_id BIGINT NOT NULL DEFAULT 0,
    "group" TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    upstream_request_id TEXT NOT NULL DEFAULT '',
    other TEXT NOT NULL DEFAULT ''
)"#;

const SQLITE_QUOTA_DATA: &str = r#"CREATE TABLE IF NOT EXISTS quota_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT NOT NULL DEFAULT 0,
    username TEXT NOT NULL DEFAULT '',
    model_name TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT 0,
    use_group TEXT NOT NULL DEFAULT '',
    token_id BIGINT NOT NULL DEFAULT 0,
    channel_id BIGINT NOT NULL DEFAULT 0,
    node_name TEXT NOT NULL DEFAULT '',
    token_used BIGINT NOT NULL DEFAULT 0,
    count BIGINT NOT NULL DEFAULT 0,
    quota BIGINT NOT NULL DEFAULT 0
)"#;

const POSTGRES_QUOTA_DATA: &str = r#"CREATE TABLE IF NOT EXISTS quota_data (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL DEFAULT 0,
    username TEXT NOT NULL DEFAULT '',
    model_name TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT 0,
    use_group TEXT NOT NULL DEFAULT '',
    token_id BIGINT NOT NULL DEFAULT 0,
    channel_id BIGINT NOT NULL DEFAULT 0,
    node_name TEXT NOT NULL DEFAULT '',
    token_used BIGINT NOT NULL DEFAULT 0,
    count BIGINT NOT NULL DEFAULT 0,
    quota BIGINT NOT NULL DEFAULT 0
)"#;

async fn sqlite_fixture() -> Database {
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .connect(":memory:")
        .await
        .expect("in-memory SQLite fixture");
    let db = Database::Sqlite(pool);
    install_schema(&db).await;
    db
}

async fn postgres_fixture() -> Option<Database> {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return None;
    };
    let options: PgConnectOptions = dsn
        .parse()
        .unwrap_or_else(|_| panic!("invalid PostgreSQL fixture config"));
    let options = options.disable_statement_logging();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .expect("connect PostgreSQL fixture");
    let schema = format!(
        "usage_write_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .expect("create isolated schema");
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _| {
            let path = search_path.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path', $1, false)")
                    .bind(path)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .expect("connect isolated PostgreSQL pool");
    let db = Database::Postgres(pool);
    install_schema(&db).await;
    Some(db)
}

async fn install_schema(db: &Database) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(SQLITE_LOGS).execute(pool).await.expect("logs");
            sqlx::query(SQLITE_QUOTA_DATA)
                .execute(pool)
                .await
                .expect("quota_data");
        }
        Database::Postgres(pool) => {
            sqlx::query(POSTGRES_LOGS)
                .execute(pool)
                .await
                .expect("logs");
            sqlx::query(POSTGRES_QUOTA_DATA)
                .execute(pool)
                .await
                .expect("quota_data");
        }
    }
}

async fn reset(db: &Database) {
    match db {
        Database::Sqlite(pool) => {
            for table in ["logs", "quota_data"] {
                sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {table}")))
                    .execute(pool)
                    .await
                    .expect("reset");
            }
        }
        Database::Postgres(pool) => {
            sqlx::query("DELETE FROM logs")
                .execute(pool)
                .await
                .expect("reset");
            sqlx::query("DELETE FROM quota_data")
                .execute(pool)
                .await
                .expect("reset");
            sqlx::query("SELECT setval(pg_get_serial_sequence('logs', 'id'), 1, false)")
                .execute(pool)
                .await
                .expect("reset logs sequence");
            sqlx::query("SELECT setval(pg_get_serial_sequence('quota_data', 'id'), 1, false)")
                .execute(pool)
                .await
                .expect("reset quota_data sequence");
        }
    }
}

fn other(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[tokio::test]
async fn record_consume_log_writes_the_read_side_projection() {
    let db = sqlite_fixture().await;
    reset(&db).await;
    let context = ConsumeLogContext {
        user_id: 7,
        username: "alice".to_owned(),
        request_id: "req-1".to_owned(),
        upstream_request_id: "up-1".to_owned(),
        record_ip: true,
        client_ip: "1.2.3.4".to_owned(),
        consume_enabled: true,
        data_export_enabled: false,
        node_name: String::new(),
    };
    let params = RecordConsumeLogParams {
        channel_id: 3,
        prompt_tokens: 100,
        completion_tokens: 20,
        model_name: "gpt-4".to_owned(),
        token_name: "tok".to_owned(),
        quota: 500,
        content: "hello".to_owned(),
        token_id: 9,
        use_time_seconds: 12,
        is_stream: true,
        group: "default".to_owned(),
        other: other(&[
            ("admin_info", json!({"server_ip": "10.0.0.1"})),
            ("audit_info", json!({"route": "/v1/chat"})),
        ]),
    };
    store_log::record_consume_log(&db, &context, &params)
        .await
        .expect("consume log insert");
    let row = store_log::read_back(&db, 1).await.unwrap().expect("row");
    assert_eq!(row.user_id, 7);
    assert_eq!(row.username, "alice");
    assert_eq!(row.log_type, store_log::LOG_TYPE_CONSUME);
    assert_eq!(row.content, "hello");
    assert_eq!(row.prompt_tokens, 100);
    assert_eq!(row.completion_tokens, 20);
    assert_eq!(row.token_name, "tok");
    assert_eq!(row.model_name, "gpt-4");
    assert_eq!(row.quota, 500);
    assert_eq!(row.channel_id, 3);
    assert_eq!(row.token_id, 9);
    assert_eq!(row.use_time, 12);
    assert!(row.is_stream);
    assert_eq!(row.group, "default");
    assert_eq!(row.ip, "1.2.3.4");
    assert_eq!(row.request_id, "req-1");
    assert_eq!(row.upstream_request_id, "up-1");
    let parsed: Value = serde_json::from_str(&row.other).unwrap();
    assert_eq!(parsed["admin_info"]["server_ip"], json!("10.0.0.1"));
    assert_eq!(parsed["audit_info"]["route"], json!("/v1/chat"));
    // other JSON 键序：BTreeMap 字典序，admin_info < audit_info。
    let keys: Vec<&String> = parsed.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["admin_info", "audit_info"]);
    drop(db);

    if let Some(pg) = postgres_fixture().await {
        reset(&pg).await;
        store_log::record_consume_log(&pg, &context, &params)
            .await
            .expect("consume log insert (pg)");
        let row = store_log::read_back(&pg, 1).await.unwrap().expect("row");
        assert_eq!(row.user_id, 7);
        assert!(row.is_stream);
        assert_eq!(row.ip, "1.2.3.4");
    } else {
        eprintln!("TEST_POSTGRES_DSN absent; PostgreSQL half skipped");
    }
}

#[tokio::test]
async fn consume_gate_and_ip_gate_match_go() {
    let db = sqlite_fixture().await;
    reset(&db).await;
    // LogConsumeEnabled=false：不写任何行。
    let context = ConsumeLogContext {
        user_id: 1,
        username: "u".to_owned(),
        consume_enabled: false,
        ..ConsumeLogContext::default()
    };
    store_log::record_consume_log(&db, &context, &RecordConsumeLogParams::default())
        .await
        .unwrap();
    assert!(store_log::read_back(&db, 1).await.unwrap().is_none());
    // RecordIpLog=false：ip 列写空串，但行照写。
    let context = ConsumeLogContext {
        user_id: 1,
        username: "u".to_owned(),
        client_ip: "5.6.7.8".to_owned(),
        record_ip: false,
        consume_enabled: true,
        ..ConsumeLogContext::default()
    };
    store_log::record_consume_log(&db, &context, &RecordConsumeLogParams::default())
        .await
        .unwrap();
    let row = store_log::read_back(&db, 1).await.unwrap().expect("row");
    assert_eq!(row.ip, "");
}

#[tokio::test]
async fn empty_request_id_gets_generated() {
    let db = sqlite_fixture().await;
    reset(&db).await;
    let context = ConsumeLogContext {
        user_id: 2,
        username: "u".to_owned(),
        consume_enabled: true,
        ..ConsumeLogContext::default()
    };
    store_log::record_consume_log(&db, &context, &RecordConsumeLogParams::default())
        .await
        .unwrap();
    let row = store_log::read_back(&db, 1).await.unwrap().expect("row");
    // Go NewRequestId：GetTimeString（14 位 UTC 时间戳 + 9 位纳秒）+ 8 位
    // 前缀 + 8 位随机 = 39。
    assert_eq!(row.request_id.len(), 14 + 9 + 8 + 8);
    assert!(row.request_id.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[tokio::test]
async fn data_export_populates_quota_data_cache_not_the_table() {
    let _guard = USEDATA_LOCK.lock().await;
    let db = sqlite_fixture().await;
    reset(&db).await;
    usedata::clear_cache();
    let context = ConsumeLogContext {
        user_id: 5,
        username: "bob".to_owned(),
        consume_enabled: true,
        data_export_enabled: true,
        node_name: "node-a".to_owned(),
        ..ConsumeLogContext::default()
    };
    let params = RecordConsumeLogParams {
        model_name: "m".to_owned(),
        quota: 100,
        prompt_tokens: 10,
        completion_tokens: 5,
        group: "g".to_owned(),
        token_id: 3,
        channel_id: 4,
        ..RecordConsumeLogParams::default()
    };
    store_log::record_consume_log(&db, &context, &params)
        .await
        .unwrap();
    // 内存聚合：created_at 只到小时。
    assert_eq!(usedata::cache_len(), 1);
    let rows = count_rows(&db, "quota_data").await;
    assert_eq!(rows, 0, "Go 只在 SaveQuotaDataCache 落库");
    let saved = usedata::save_quota_data_cache(&db).await.unwrap();
    assert_eq!(saved, 1);
    let now = Utc::now().timestamp();
    let hour_floor = now - now % 3600;
    let entry = usedata::QuotaDataAgg {
        user_id: 5,
        username: "bob".to_owned(),
        model_name: "m".to_owned(),
        created_at: hour_floor,
        use_group: "g".to_owned(),
        token_id: 3,
        channel_id: 4,
        node_name: "node-a".to_owned(),
        ..Default::default()
    };
    let (count, quota, token_used) = usedata::read_back(&db, &entry)
        .await
        .unwrap()
        .expect("quota_data row");
    assert_eq!((count, quota, token_used), (1, 100, 15));
    // 再来一次同键聚合 + 落库：累加而不是新行。
    store_log::record_consume_log(&db, &context, &params)
        .await
        .unwrap();
    usedata::save_quota_data_cache(&db).await.unwrap();
    let (count, quota, token_used) = usedata::read_back(&db, &entry)
        .await
        .unwrap()
        .expect("quota_data row");
    assert_eq!((count, quota, token_used), (2, 200, 30));
    assert_eq!(count_rows(&db, "quota_data").await, 1);
}

async fn count_rows(db: &Database, table: &str) -> i64 {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                .fetch_one(pool)
                .await
                .unwrap()
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                .fetch_one(pool)
                .await
                .unwrap()
        }
    }
}

#[tokio::test]
async fn hour_floor_aggregation_merges_same_hour() {
    let _guard = USEDATA_LOCK.lock().await;
    let db = sqlite_fixture().await;
    reset(&db).await;
    usedata::clear_cache();
    usedata::log_quota_data(QuotaDataLogParams {
        user_id: 1,
        username: "u".to_owned(),
        model_name: "m".to_owned(),
        quota: 10,
        created_at: 3600,
        token_used: 3,
        use_group: "g".to_owned(),
        ..QuotaDataLogParams::default()
    });
    usedata::log_quota_data(QuotaDataLogParams {
        user_id: 1,
        username: "u".to_owned(),
        model_name: "m".to_owned(),
        quota: 5,
        created_at: 3611,
        token_used: 7,
        use_group: "g".to_owned(),
        ..QuotaDataLogParams::default()
    });
    assert_eq!(usedata::cache_len(), 1, "同一小时聚合为一条");
    let entry = usedata::QuotaDataAgg {
        user_id: 1,
        username: "u".to_owned(),
        model_name: "m".to_owned(),
        created_at: 3600,
        use_group: "g".to_owned(),
        ..Default::default()
    };
    usedata::save_quota_data_cache(&db).await.unwrap();
    let (count, quota, token_used) = usedata::read_back(&db, &entry).await.unwrap().expect("row");
    assert_eq!((count, quota, token_used), (2, 15, 10));
}

#[tokio::test]
async fn other_write_shapes_follow_the_go_functions() {
    let db = sqlite_fixture().await;
    reset(&db).await;
    // RecordLog / RecordLogWithAdminInfo。
    store_log::record_log(&db, "admin", 1, store_log::LOG_TYPE_SYSTEM, "sys", false)
        .await
        .unwrap();
    let row = store_log::read_back(&db, 1).await.unwrap().unwrap();
    assert_eq!(row.log_type, store_log::LOG_TYPE_SYSTEM);
    assert_eq!(row.other, "");
    let mut admin_info = Map::new();
    admin_info.insert("k".to_owned(), json!("v"));
    store_log::record_log_with_admin_info(
        &db,
        "admin",
        1,
        store_log::LOG_TYPE_MANAGE,
        "op",
        &admin_info,
        false,
    )
    .await
    .unwrap();
    let row = store_log::read_back(&db, 2).await.unwrap().unwrap();
    assert_eq!(row.other, r#"{"admin_info":{"k":"v"}}"#);
    // RecordLoginLog：op 后写、extra 先入。
    let mut extra = Map::new();
    extra.insert("login_method".to_owned(), json!("password"));
    store_log::record_login_log(
        &db,
        2,
        "alice",
        "logged in",
        "1.1.1.1",
        &store_log::LoginAuditParams {
            action: "login",
            op_params: &Map::new(),
            extra: &extra,
        },
    )
    .await
    .unwrap();
    let row = store_log::read_back(&db, 3).await.unwrap().unwrap();
    assert_eq!(row.log_type, store_log::LOG_TYPE_LOGIN);
    assert_eq!(row.ip, "1.1.1.1");
    let parsed: Value = serde_json::from_str(&row.other).unwrap();
    assert_eq!(parsed["op"]["action"], json!("login"));
    assert_eq!(parsed["login_method"], json!("password"));
    // RecordOperationAuditLog。
    store_log::record_operation_audit_log(
        &db,
        2,
        "alice",
        "audit",
        "1.1.1.1",
        &store_log::OperationAuditParams {
            action: "channel.add",
            params: &Map::new(),
            admin_info: &admin_info,
            audit_info: &Map::new(),
        },
    )
    .await
    .unwrap();
    let row = store_log::read_back(&db, 4).await.unwrap().unwrap();
    let parsed: Value = serde_json::from_str(&row.other).unwrap();
    assert_eq!(parsed["op"]["action"], json!("channel.add"));
    assert_eq!(parsed["admin_info"]["k"], json!("v"));
    assert!(parsed.get("audit_info").is_none());
    // RecordSensitiveAuditLog。
    store_log::record_sensitive_audit_log(&db, 3, "bob", "blocked", "2.2.2.2", &Map::new())
        .await
        .unwrap();
    let row = store_log::read_back(&db, 5).await.unwrap().unwrap();
    assert_eq!(row.log_type, store_log::LOG_TYPE_SENSITIVE);
    let parsed: Value = serde_json::from_str(&row.other).unwrap();
    assert_eq!(parsed["op"]["action"], json!("sensitive_block"));
    // RecordTopupLog。
    store_log::record_topup_log(
        &db,
        3,
        "bob",
        "topup",
        &TopupAdminInfo {
            server_ip: "10.0.0.9".to_owned(),
            node_name: "n".to_owned(),
            caller_ip: "3.3.3.3".to_owned(),
            payment_method: "wxpay".to_owned(),
            callback_payment_method: "alipay".to_owned(),
            version: "v1".to_owned(),
        },
    )
    .await
    .unwrap();
    let row = store_log::read_back(&db, 6).await.unwrap().unwrap();
    assert_eq!(row.log_type, store_log::LOG_TYPE_TOPUP);
    let parsed: Value = serde_json::from_str(&row.other).unwrap();
    let admin = parsed["admin_info"].as_object().unwrap();
    assert_eq!(
        admin.keys().collect::<Vec<_>>(),
        [
            "callback_payment_method",
            "caller_ip",
            "node_name",
            "payment_method",
            "server_ip",
            "version"
        ],
        "admin_info 键为字典序"
    );
    // RecordErrorLog。
    let context = ConsumeLogContext {
        user_id: 4,
        username: "carol".to_owned(),
        record_ip: true,
        client_ip: "4.4.4.4".to_owned(),
        ..ConsumeLogContext::default()
    };
    let empty_other = Map::new();
    store_log::record_error_log(
        &db,
        &context,
        &store_log::ErrorLogParams {
            channel_id: 8,
            model_name: "m",
            token_name: "t",
            content: "boom",
            token_id: 5,
            use_time_seconds: 3,
            is_stream: false,
            group: "g",
            other: &empty_other,
        },
    )
    .await
    .unwrap();
    let row = store_log::read_back(&db, 7).await.unwrap().unwrap();
    assert_eq!(row.log_type, store_log::LOG_TYPE_ERROR);
    assert_eq!(
        (row.prompt_tokens, row.completion_tokens, row.quota),
        (0, 0, 0)
    );
    assert_eq!(row.channel_id, 8);
    assert_eq!(row.use_time, 3);
    // RecordTaskBillingLog。
    let params = store_log::TaskBillingLogParams {
        log_type: store_log::LOG_TYPE_CONSUME,
        content: "task".to_owned(),
        channel_id: 0,
        model_name: "m".to_owned(),
        quota: 42,
        token_id: 0,
        group: "g".to_owned(),
        other: Map::new(),
        node_name: String::new(),
        token_name: String::new(),
        consume_enabled: true,
        data_export_enabled: true,
        default_node_name: "node-default".to_owned(),
    };
    store_log::record_task_billing_log(&db, 4, "carol", &params)
        .await
        .unwrap();
    let row = store_log::read_back(&db, 8).await.unwrap().unwrap();
    assert_eq!(row.username, "carol");
    assert_eq!(row.quota, 42);
}

#[tokio::test]
async fn task_billing_log_consume_gate_and_node_fallback() {
    let _guard = USEDATA_LOCK.lock().await;
    let db = sqlite_fixture().await;
    reset(&db).await;
    usedata::clear_cache();
    let params = store_log::TaskBillingLogParams {
        log_type: store_log::LOG_TYPE_CONSUME,
        content: "task".to_owned(),
        default_node_name: "node-x".to_owned(),
        ..store_log::TaskBillingLogParams::default()
    };
    store_log::record_task_billing_log(&db, 1, "u", &params)
        .await
        .unwrap();
    assert!(store_log::read_back(&db, 1).await.unwrap().is_none());
    store_log::record_task_billing_log(
        &db,
        1,
        "u",
        &store_log::TaskBillingLogParams {
            consume_enabled: true,
            data_export_enabled: true,
            ..params.clone()
        },
    )
    .await
    .unwrap();
    assert_eq!(usedata::cache_len(), 1);
}
