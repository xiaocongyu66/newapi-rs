//! 网关路由修订机制的双后端契约（SQLite 内存 + 独立 PostgreSQL schema）。
//!
//! 只跑真实 sqlx 后端；PG 变体在 `TEST_POSTGRES_DSN` 缺失时跳过（P1 CI
//! 注入该变量）。断言对齐 Go `catalog/store_gateway_revision.go` 与
//! `gateway_config_revision_test.go` 的可观察契约：
//!
//! - 空库初始化出修订号 1；重复初始化绝不倒退已有水位。
//! - 一次路由可见变更（`mutate_routing!` / 仓储写路径）= 恰好一次 bump +
//!   一条 outbox 行，同事务提交。
//! - mutator 失败 → 域写入、修订号、outbox 整体回滚（水位不推进，绝不
//!   退化成 0）。
//! - 单例行缺失 / 水位非正 → 硬错误（`GatewayRevisionError`）。
//! - 顺序变更严格递增；并发成功提交拿到**不同**且递增的修订号
//!   （单行 UPDATE 行锁串行化）。
//! - outbox `routing_revision` 唯一；仓储批量删除整批只推进一次。

use newapi_catalog::channels::{ChannelInfo, ChannelRepository, NewChannel};
use newapi_catalog::gateway_revision::{
    self, GatewayOutboxRow, GatewayRevisionError, current_gateway_revision,
    initialize_gateway_config_revision, list_pending_gateway_config_outbox,
};
use newapi_catalog::models::{ModelRepository, NewModel};
use newapi_catalog::mutate_routing;
use newapi_storage::Database;
use sqlx::{
    ConnectOptions,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

const GATEWAY_REVISION_SQLITE: &str = r#"CREATE TABLE gateway_config_revisions (
    id BIGINT PRIMARY KEY,
    routing_revision BIGINT NOT NULL
)"#;

const GATEWAY_REVISION_POSTGRES: &str = r#"CREATE TABLE gateway_config_revisions (
    id BIGINT PRIMARY KEY,
    routing_revision BIGINT NOT NULL
)"#;

const GATEWAY_OUTBOX_SQLITE: &str = r#"CREATE TABLE gateway_config_outboxes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    routing_revision BIGINT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP,
    publish_attempts INTEGER NOT NULL DEFAULT 0,
    last_publish_error_class VARCHAR(64)
)"#;

const GATEWAY_OUTBOX_POSTGRES: &str = r#"CREATE TABLE gateway_config_outboxes (
    id BIGSERIAL PRIMARY KEY,
    routing_revision BIGINT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    published_at TIMESTAMP,
    publish_attempts INTEGER NOT NULL DEFAULT 0,
    last_publish_error_class VARCHAR(64)
)"#;

const CHANNELS_SQLITE: &str = r#"CREATE TABLE channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    "type" INTEGER NOT NULL DEFAULT 0,
    "key" TEXT NOT NULL,
    openai_organization TEXT,
    test_model TEXT,
    status INTEGER NOT NULL DEFAULT 1,
    name TEXT NOT NULL,
    created_time INTEGER NOT NULL DEFAULT 0,
    test_time INTEGER NOT NULL DEFAULT 0,
    response_time INTEGER NOT NULL DEFAULT 0,
    base_url TEXT NOT NULL DEFAULT '',
    other TEXT NOT NULL DEFAULT '',
    balance REAL NOT NULL DEFAULT 0,
    balance_updated_time INTEGER NOT NULL DEFAULT 0,
    models TEXT NOT NULL DEFAULT '',
    "group" VARCHAR(64) NOT NULL DEFAULT 'default',
    used_quota BIGINT NOT NULL DEFAULT 0,
    model_mapping TEXT,
    status_code_mapping VARCHAR(1024) NOT NULL DEFAULT '',
    auto_ban INTEGER DEFAULT 1,
    other_info TEXT NOT NULL DEFAULT '',
    tag TEXT,
    setting TEXT,
    param_override TEXT,
    header_override TEXT,
    remark VARCHAR(255),
    channel_info TEXT NOT NULL DEFAULT '{}',
    settings TEXT NOT NULL DEFAULT ''
)"#;

const CHANNELS_POSTGRES: &str = r#"CREATE TABLE channels (
    id BIGSERIAL PRIMARY KEY,
    "type" BIGINT NOT NULL DEFAULT 0,
    "key" TEXT NOT NULL,
    openai_organization TEXT,
    test_model TEXT,
    status BIGINT NOT NULL DEFAULT 1,
    name TEXT NOT NULL,
    created_time BIGINT NOT NULL DEFAULT 0,
    test_time BIGINT NOT NULL DEFAULT 0,
    response_time BIGINT NOT NULL DEFAULT 0,
    base_url TEXT NOT NULL DEFAULT '',
    other TEXT NOT NULL DEFAULT '',
    balance DOUBLE PRECISION NOT NULL DEFAULT 0,
    balance_updated_time BIGINT NOT NULL DEFAULT 0,
    models TEXT NOT NULL DEFAULT '',
    "group" VARCHAR(64) NOT NULL DEFAULT 'default',
    used_quota BIGINT NOT NULL DEFAULT 0,
    model_mapping TEXT,
    status_code_mapping VARCHAR(1024) NOT NULL DEFAULT '',
    auto_ban BIGINT DEFAULT 1,
    other_info TEXT NOT NULL DEFAULT '',
    tag TEXT,
    setting TEXT,
    param_override TEXT,
    header_override TEXT,
    remark VARCHAR(255),
    channel_info TEXT NOT NULL DEFAULT '{}',
    settings TEXT NOT NULL DEFAULT ''
)"#;

const ABILITIES_SQLITE: &str = r#"CREATE TABLE abilities (
    "group" VARCHAR(64) NOT NULL,
    model VARCHAR(255) NOT NULL,
    channel_id INTEGER NOT NULL,
    enabled BOOLEAN NOT NULL,
    tag TEXT,
    PRIMARY KEY ("group", model, channel_id)
)"#;

const ABILITIES_POSTGRES: &str = r#"CREATE TABLE abilities (
    "group" VARCHAR(64) NOT NULL,
    model VARCHAR(255) NOT NULL,
    channel_id BIGINT NOT NULL,
    enabled BOOLEAN NOT NULL,
    tag TEXT,
    PRIMARY KEY ("group", model, channel_id)
)"#;

const MODELS_SQLITE: &str = r#"CREATE TABLE models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name VARCHAR(128) NOT NULL,
    description TEXT,
    icon VARCHAR(128),
    tags VARCHAR(255),
    vendor_id INTEGER,
    endpoints TEXT,
    status INTEGER DEFAULT 1,
    sync_official INTEGER DEFAULT 1,
    created_time BIGINT,
    updated_time BIGINT,
    deleted_at TIMESTAMP,
    name_rule INTEGER DEFAULT 0
)"#;

const MODELS_POSTGRES: &str = r#"CREATE TABLE models (
    id BIGSERIAL PRIMARY KEY,
    model_name VARCHAR(128) NOT NULL,
    description TEXT,
    icon VARCHAR(128),
    tags VARCHAR(255),
    vendor_id BIGINT,
    endpoints TEXT,
    status BIGINT DEFAULT 1,
    sync_official BIGINT DEFAULT 1,
    created_time BIGINT,
    updated_time BIGINT,
    deleted_at TIMESTAMPTZ,
    name_rule BIGINT DEFAULT 0
)"#;

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
            for statement in [
                GATEWAY_REVISION_SQLITE,
                GATEWAY_OUTBOX_SQLITE,
                CHANNELS_SQLITE,
                ABILITIES_SQLITE,
                MODELS_SQLITE,
            ] {
                execute(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                GATEWAY_REVISION_POSTGRES,
                GATEWAY_OUTBOX_POSTGRES,
                CHANNELS_POSTGRES,
                ABILITIES_POSTGRES,
                MODELS_POSTGRES,
            ] {
                execute(db, statement).await;
            }
        }
    }
    initialize_gateway_config_revision(db).await.unwrap();
}

/// Go `resetGatewayRevision`（`gateway_config_revision_test.go:15-24`）：
/// 清空修订/outbox/域表后种入指定水位，从已知提交态出发。
async fn reset_revision(db: &Database, revision: i64) {
    for statement in [
        "DELETE FROM gateway_config_outboxes",
        "DELETE FROM gateway_config_revisions",
        "DELETE FROM abilities",
        "DELETE FROM channels",
        "DELETE FROM models",
    ] {
        execute(db, statement).await;
    }
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO gateway_config_revisions (id, routing_revision) VALUES (?, ?)",
            )
            .bind(newapi_catalog::gateway_revision::GATEWAY_CONFIG_REVISION_ID)
            .bind(revision)
            .execute(pool)
            .await
            .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "INSERT INTO gateway_config_revisions (id, routing_revision) VALUES ($1, $2)",
            )
            .bind(newapi_catalog::gateway_revision::GATEWAY_CONFIG_REVISION_ID)
            .bind(revision)
            .execute(pool)
            .await
            .unwrap();
        }
    }
}

async fn outbox_revisions(db: &Database) -> Vec<i64> {
    match db {
        Database::Sqlite(pool) => sqlx::query_scalar::<_, i64>(
            "SELECT routing_revision FROM gateway_config_outboxes ORDER BY routing_revision ASC",
        )
        .fetch_all(pool)
        .await
        .unwrap(),
        Database::Postgres(pool) => sqlx::query_scalar::<_, i64>(
            "SELECT routing_revision FROM gateway_config_outboxes ORDER BY routing_revision ASC",
        )
        .fetch_all(pool)
        .await
        .unwrap(),
    }
}

async fn revision_row_count(db: &Database) -> i64 {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM gateway_config_revisions")
                .fetch_one(pool)
                .await
                .unwrap()
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM gateway_config_revisions")
                .fetch_one(pool)
                .await
                .unwrap()
        }
    }
}

async fn channel_count_by_name(db: &Database, name: &str) -> i64 {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM channels WHERE name = ?")
                .bind(name)
                .fetch_one(pool)
                .await
                .unwrap()
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM channels WHERE name = $1")
                .bind(name)
                .fetch_one(pool)
                .await
                .unwrap()
        }
    }
}

fn revision_error_of(error: &sqlx::Error) -> &GatewayRevisionError {
    match error {
        sqlx::Error::Configuration(boxed) => boxed
            .downcast_ref::<GatewayRevisionError>()
            .expect("configuration error carries GatewayRevisionError"),
        other => panic!("expected sqlx::Error::Configuration, got {other:?}"),
    }
}

fn new_channel(name: &str, key: &str, models: &str) -> NewChannel {
    NewChannel {
        channel_type: 1,
        key: key.to_owned(),
        openai_organization: None,
        test_model: None,
        status: newapi_catalog::channels::CHANNEL_STATUS_ENABLED,
        name: name.to_owned(),
        created_time: 0,
        base_url: String::new(),
        other: String::new(),
        models: models.to_owned(),
        group: "default".to_owned(),
        model_mapping: None,
        status_code_mapping: String::new(),
        auto_ban: 1,
        other_info: String::new(),
        tag: None,
        setting: None,
        param_override: None,
        header_override: None,
        remark: None,
        channel_info: ChannelInfo::default(),
        settings: String::new(),
    }
}

async fn contract(db: &Database) {
    // -- 初始化：空库 → 修订号 1；重复初始化绝不倒退；表保持单例 --
    assert_eq!(current_gateway_revision(db).await.unwrap(), 1);
    mutate_routing!(db, _tx, { Ok(()) }).unwrap();
    assert_eq!(current_gateway_revision(db).await.unwrap(), 2);
    initialize_gateway_config_revision(db).await.unwrap();
    assert_eq!(
        current_gateway_revision(db).await.unwrap(),
        2,
        "re-initialisation must never reset a live watermark"
    );
    assert_eq!(revision_row_count(db).await, 1);

    // -- 一次变更 = 一个修订号 + 一条 outbox 行 + 域写入同提交 --
    reset_revision(db, 7).await;
    let channels = ChannelRepository::new(db.clone());
    channels
        .insert_channels(vec![new_channel("revision-probe", "k-probe", "m1,m2")])
        .await
        .unwrap();
    assert_eq!(current_gateway_revision(db).await.unwrap(), 8);
    assert_eq!(outbox_revisions(db).await, vec![8]);
    assert_eq!(channel_count_by_name(db, "revision-probe").await, 1);
    let pending: Vec<GatewayOutboxRow> = list_pending_gateway_config_outbox(db, 10).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].routing_revision, 8);

    // -- mutator 失败：域写入、修订号、outbox 整体回滚 --
    reset_revision(db, 4).await;
    let error = mutate_routing!(db, tx, {
        sqlx::query("INSERT INTO channels (name, \"key\") VALUES ($1, $2)")
            .bind("revision-rollback-probe")
            .bind("k-rollback")
            .execute(&mut *tx)
            .await?;
        Err::<(), sqlx::Error>(sqlx::Error::RowNotFound)
    })
    .unwrap_err();
    assert!(matches!(error, sqlx::Error::RowNotFound));
    assert_eq!(
        current_gateway_revision(db).await.unwrap(),
        4,
        "failed mutation must not advance the watermark"
    );
    assert!(outbox_revisions(db).await.is_empty());
    assert_eq!(
        channel_count_by_name(db, "revision-rollback-probe").await,
        0
    );

    // -- 单例行缺失：绝不退化成 0 修订号 --
    reset_revision(db, 1).await;
    execute(db, "DELETE FROM gateway_config_revisions").await;
    let error = mutate_routing!(db, _tx, { Ok(()) }).unwrap_err();
    assert!(matches!(
        revision_error_of(&error),
        GatewayRevisionError::RowMissing
    ));
    assert!(outbox_revisions(db).await.is_empty());

    // -- 水位非正：硬错误，原样回滚不动 --
    reset_revision(db, -1).await;
    let error = mutate_routing!(db, _tx, { Ok(()) }).unwrap_err();
    assert!(matches!(
        revision_error_of(&error),
        GatewayRevisionError::NotPositive(-1)
    ));
    assert_eq!(current_gateway_revision(db).await.unwrap(), -1);
    assert!(outbox_revisions(db).await.is_empty());

    // -- 顺序变更严格递增，outbox 顺序一致 --
    reset_revision(db, 1).await;
    let mut got = Vec::new();
    for _ in 0..5 {
        got.push(mutate_routing!(db, _tx, { Ok(()) }).unwrap());
    }
    assert_eq!(got, vec![2, 3, 4, 5, 6]);
    assert_eq!(outbox_revisions(db).await, got);

    // -- outbox routing_revision 唯一：一个修订号只发布一次 --
    let error = match db {
        Database::Sqlite(pool) => sqlx::query(
            "INSERT INTO gateway_config_outboxes (routing_revision, created_at) \
             VALUES (?, CURRENT_TIMESTAMP)",
        )
        .bind(6i64)
        .execute(pool)
        .await
        .unwrap_err(),
        Database::Postgres(pool) => sqlx::query(
            "INSERT INTO gateway_config_outboxes (routing_revision, created_at) \
             VALUES ($1, CURRENT_TIMESTAMP)",
        )
        .bind(6i64)
        .execute(pool)
        .await
        .unwrap_err(),
    };
    assert!(
        !matches!(error, sqlx::Error::Configuration(_)),
        "duplicate outbox revision must violate the unique index, got {error:?}"
    );

    // -- 并发成功提交：修订号互不相同且递增（行锁串行化 bump）--
    reset_revision(db, 1).await;
    let db_a = db.clone();
    let db_b = db.clone();
    let (left, right) = tokio::join!(
        async move { mutate_routing!(db_a, _tx, { Ok(()) }).unwrap() },
        async move { mutate_routing!(db_b, _tx, { Ok(()) }).unwrap() },
    );
    assert_ne!(
        left, right,
        "two concurrent committed mutations must get distinct revisions"
    );
    assert!(left >= 2 && right >= 2);
    let mut outbox = outbox_revisions(db).await;
    outbox.sort_unstable();
    assert_eq!(
        outbox,
        {
            let mut both = vec![left, right];
            both.sort_unstable();
            both
        },
        "each committed mutation published exactly one outbox row"
    );

    // -- 仓储接入：模型写路径逐次推进修订号 --
    reset_revision(db, 10).await;
    let models = ModelRepository::new(db.clone());
    let new_model = NewModel {
        id: None,
        model_name: "revision-model".to_owned(),
        description: String::new(),
        icon: String::new(),
        tags: String::new(),
        vendor_id: 0,
        endpoints: String::new(),
        status: 1,
        sync_official: 1,
        name_rule: 0,
    };
    let model_id = models.insert(&new_model, 1000).await.unwrap();
    assert_eq!(current_gateway_revision(db).await.unwrap(), 11);
    models.update_status(model_id, 0).await.unwrap();
    assert_eq!(current_gateway_revision(db).await.unwrap(), 12);
    assert!(models.soft_delete(model_id, 2000).await.unwrap());
    assert_eq!(current_gateway_revision(db).await.unwrap(), 13);
    assert_eq!(outbox_revisions(db).await, vec![11, 12, 13]);

    // -- 仓储接入：批量删除整批只推进一次修订号 --
    reset_revision(db, 20).await;
    for index in 0..3 {
        channels
            .insert_channels(vec![new_channel(
                &format!("bulk-{index}"),
                &format!("k-bulk-{index}"),
                "m1",
            )])
            .await
            .expect("seed bulk channel");
    }
    let before = current_gateway_revision(db).await.unwrap();
    let ids: Vec<i64> = match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar::<_, i64>("SELECT id FROM channels WHERE name LIKE 'bulk-%'")
                .fetch_all(pool)
                .await
                .unwrap()
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar::<_, i64>("SELECT id FROM channels WHERE name LIKE 'bulk-%'")
                .fetch_all(pool)
                .await
                .unwrap()
        }
    };
    assert_eq!(ids.len(), 3);
    let deleted = channels.delete_by_ids(&ids).await.unwrap();
    assert_eq!(deleted, 3);
    assert_eq!(
        current_gateway_revision(db).await.unwrap(),
        before + 1,
        "the whole batch is one mutation: exactly one revision bump"
    );
    let outbox = outbox_revisions(db).await;
    assert_eq!(outbox.last().copied(), Some(before + 1));
}

#[tokio::test]
async fn sqlite_gateway_revision_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(SqliteConnectOptions::new().in_memory(true))
        .await
        .unwrap();
    contract(&Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_gateway_revision_contract() {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return;
    };
    let options: sqlx::postgres::PgConnectOptions = dsn.parse().unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone().disable_statement_logging())
        .await
        .unwrap();
    let schema = format!("gateway_revision_{}", std::process::id());
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
                sqlx::query("SELECT set_config('search_path', $1, false)")
                    .bind(path)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options.disable_statement_logging())
        .await
        .unwrap();
    contract(&Database::Postgres(pool.clone())).await;
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .unwrap();
    admin.close().await;
}
