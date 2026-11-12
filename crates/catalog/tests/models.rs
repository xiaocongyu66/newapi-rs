//! 模型元数据仓储的双后端契约（SQLite 内存 + 独立 PostgreSQL schema）。
//!
//! 只跑真实 sqlx 后端；PG 变体在 `TEST_POSTGRES_DSN` 缺失时跳过（P1 CI
//! 注入该变量）。断言对齐 Go `catalog/store_model_meta.go` /
//! `store_missing_models.go` / `store_vendor_meta.go` 的可观察行为：
//! 软删除范围、搜索谓词与排序、重名检查、整列覆写、绑定渠道聚合、
//! 缺失模型、供应商补建。

use std::collections::BTreeMap;

use newapi_catalog::abilities;
use newapi_catalog::models::{
    BoundChannel, ModelInput, ModelRepository, NewModel, choose_status, contains_field,
    parse_status_filter, parse_sync_filter,
};
use newapi_storage::Database;
use sqlx::{
    ConnectOptions,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

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

const VENDORS_SQLITE: &str = r#"CREATE TABLE vendors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    icon VARCHAR(128),
    status INTEGER DEFAULT 1,
    created_time BIGINT,
    updated_time BIGINT,
    deleted_at TIMESTAMP
)"#;

const VENDORS_POSTGRES: &str = r#"CREATE TABLE vendors (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    icon VARCHAR(128),
    status BIGINT DEFAULT 1,
    created_time BIGINT,
    updated_time BIGINT,
    deleted_at TIMESTAMPTZ
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

const CHANNELS_SQLITE: &str = r#"CREATE TABLE channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    "type" INTEGER NOT NULL DEFAULT 0,
    status INTEGER NOT NULL DEFAULT 1
)"#;

const CHANNELS_POSTGRES: &str = r#"CREATE TABLE channels (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    "type" BIGINT NOT NULL DEFAULT 0,
    status BIGINT NOT NULL DEFAULT 1
)"#;

// 网关路由修订表（Go `GatewayConfigRevision`/`GatewayConfigOutbox`）：
// 模型/供应商写路径经 `mutate_routing!` 提交时推进水位并写 outbox。
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
                MODELS_SQLITE,
                VENDORS_SQLITE,
                CHANNELS_SQLITE,
                ABILITIES_SQLITE,
                GATEWAY_REVISION_SQLITE,
                GATEWAY_OUTBOX_SQLITE,
            ] {
                execute(db, statement).await;
            }
        }
        Database::Postgres(_) => {
            for statement in [
                MODELS_POSTGRES,
                VENDORS_POSTGRES,
                CHANNELS_POSTGRES,
                ABILITIES_POSTGRES,
                GATEWAY_REVISION_POSTGRES,
                GATEWAY_OUTBOX_POSTGRES,
            ] {
                execute(db, statement).await;
            }
        }
    }
    // 模型/供应商写路径提交时推进网关路由修订号，水位单例行必须存在。
    newapi_catalog::gateway_revision::initialize_gateway_config_revision(db)
        .await
        .unwrap();
}

async fn reset(db: &Database) {
    execute(db, "DELETE FROM abilities").await;
    execute(db, "DELETE FROM channels").await;
    execute(db, "DELETE FROM vendors").await;
    execute(db, "DELETE FROM models").await;
}

async fn seed_model(db: &Database, id: i64, name: &str, name_rule: i64, sync_official: i64) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO models (id, model_name, name_rule, sync_official, updated_time) \
                 VALUES (?,?,?,?,0)",
            )
            .bind(id)
            .bind(name)
            .bind(name_rule)
            .bind(sync_official)
            .execute(pool)
            .await
            .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "INSERT INTO models (id, model_name, name_rule, sync_official, updated_time) \
                 VALUES ($1,$2,$3,$4,0)",
            )
            .bind(id)
            .bind(name)
            .bind(name_rule)
            .bind(sync_official)
            .execute(pool)
            .await
            .unwrap();
        }
    }
}

async fn seed_soft_deleted(db: &Database, id: i64, name: &str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO models (id, model_name, deleted_at) VALUES (?,?,1)")
                .bind(id)
                .bind(name)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO models (id, model_name, deleted_at) VALUES ($1,$2,NOW())")
                .bind(id)
                .bind(name)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

async fn seed_channel(db: &Database, id: i64, name: &str, channel_type: i64) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO channels (id, name, \"type\") VALUES (?,?,?)")
                .bind(id)
                .bind(name)
                .bind(channel_type)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO channels (id, name, \"type\") VALUES ($1,$2,$3)")
                .bind(id)
                .bind(name)
                .bind(channel_type)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

async fn seed_ability(db: &Database, group: &str, model: &str, channel_id: i64, enabled: bool) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO abilities (\"group\", model, channel_id, enabled) \
                 VALUES (?,?,?,?)",
            )
            .bind(group)
            .bind(model)
            .bind(channel_id)
            .bind(enabled)
            .execute(pool)
            .await
            .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "INSERT INTO abilities (\"group\", model, channel_id, enabled) \
                 VALUES ($1,$2,$3,$4)",
            )
            .bind(group)
            .bind(model)
            .bind(channel_id)
            .bind(enabled)
            .execute(pool)
            .await
            .unwrap();
        }
    }
}

async fn model_row(db: &Database, id: i64) -> (i64, String, i64, i64, i64) {
    match db {
        Database::Sqlite(pool) => sqlx::query_as::<_, (i64, String, i64, i64, i64)>(
            "SELECT CAST(id AS BIGINT), model_name, CAST(status AS BIGINT), \
                 CAST(sync_official AS BIGINT), CAST(updated_time AS BIGINT) \
                 FROM models WHERE id = ?",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap(),
        Database::Postgres(pool) => sqlx::query_as::<_, (i64, String, i64, i64, i64)>(
            "SELECT id, model_name, status, sync_official, updated_time \
                 FROM models WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap(),
    }
}

#[tokio::test]
async fn sqlite_models_store_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(SqliteConnectOptions::new().in_memory(true))
        .await
        .unwrap();
    contract(&Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_models_store_contract() {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return;
    };
    let options: sqlx::postgres::PgConnectOptions = dsn.parse().unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone().disable_statement_logging())
        .await
        .unwrap();
    let schema = format!("models_store_{}", std::process::id());
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
        .max_connections(2)
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

async fn contract(db: &Database) {
    create_schema(db).await;
    reset(db).await;
    let repository = ModelRepository::new(db.clone());

    // ---- 纯函数：过滤解析与 sync 工具 ------------------------------
    assert_eq!(parse_status_filter("ENABLED"), Some(1));
    assert_eq!(parse_status_filter("0"), Some(0));
    assert_eq!(parse_status_filter("nope"), None);
    assert_eq!(parse_sync_filter("YES"), Some(1));
    assert_eq!(parse_sync_filter("zz"), None);
    assert_eq!(choose_status(0, 2), 2);
    assert_eq!(choose_status(3, 2), 3);
    assert_eq!(choose_status(0, 0), 1);
    assert!(contains_field(&["STATUS".to_owned()], "status"));

    // ---- 创建：零值 status/sync_official 如实落库（Go insertWithTx 语义）
    let now = 1_700_000_000;
    let id = repository
        .insert(
            &NewModel {
                model_name: "m-zero".to_owned(),
                status: 0,
                sync_official: 0,
                ..NewModel::default()
            },
            now,
        )
        .await
        .unwrap();
    let (row_id, _, status, sync_official, updated_time) = model_row(db, id).await;
    assert_eq!(row_id, id);
    assert_eq!(status, 0);
    assert_eq!(sync_official, 0);
    assert_eq!(updated_time, now);

    // 显式 id 插入（Go `tx.Create(mi)` 对非零 id 的行为）。
    let explicit = repository
        .insert(
            &NewModel {
                id: Some(42),
                model_name: "m-explicit".to_owned(),
                status: 1,
                sync_official: 1,
                ..NewModel::default()
            },
            now,
        )
        .await
        .unwrap();
    assert_eq!(explicit, 42);

    // ---- 重名检查：排除自身与软删除行 ------------------------------
    assert!(repository.is_name_duplicated(42, "m-zero").await.unwrap());
    assert!(
        !repository
            .is_name_duplicated(42, "m-explicit")
            .await
            .unwrap()
    );
    assert!(!repository.is_name_duplicated(0, "").await.unwrap());
    seed_soft_deleted(db, 99, "m-gone").await;
    assert!(!repository.is_name_duplicated(0, "m-gone").await.unwrap());

    // ---- 读取：软删除范围生效 --------------------------------------
    assert!(repository.by_id(99).await.unwrap().is_none());
    assert!(repository.by_id(42).await.unwrap().is_some());
    assert!(repository.by_name("m-gone").await.unwrap().is_none());
    assert!(repository.by_name("m-explicit").await.unwrap().is_some());

    // ---- 搜索：keyword / vendor / status / sync_official / 排序 ------
    seed_model(db, 2, "gpt-alpha", 0, 1).await;
    seed_model(db, 3, "gpt-beta", 1, 0).await;
    seed_model(db, 4, "claude", 0, 1).await;
    execute(
        db,
        "UPDATE models SET description = 'fast model', tags = 'tag-a' WHERE id = 2",
    )
    .await;

    let (rows, total) = repository.search("", "", None, None, 0, 10).await.unwrap();
    // 软删除的 99 不计；排序 id DESC。
    // 存活 5 行：m-zero、m-explicit、gpt-alpha、gpt-beta、claude；99 已软删。
    assert_eq!(total, 5);
    let names: Vec<&str> = rows.iter().map(|row| row.model_name.as_str()).collect();
    assert_eq!(
        names,
        vec!["m-explicit", "claude", "gpt-beta", "gpt-alpha", "m-zero"]
    );

    let (rows, total) = repository
        .search("gpt", "", None, None, 0, 10)
        .await
        .unwrap();
    assert_eq!(total, 2);
    assert!(rows.iter().all(|row| row.model_name.starts_with("gpt")));

    // description/tags 也参与 keyword 匹配。
    let (_, total) = repository
        .search("fast model", "", None, None, 0, 10)
        .await
        .unwrap();
    assert_eq!(total, 1);
    let (_, total) = repository
        .search("tag-a", "", None, None, 0, 10)
        .await
        .unwrap();
    assert_eq!(total, 1);

    // vendor：数字 → vendor_id 等值；文本 → vendors.name LIKE。
    execute(db, "INSERT INTO vendors (id, name) VALUES (7, 'OpenAI')").await;
    execute(db, "UPDATE models SET vendor_id = 7 WHERE id = 4").await;
    let (_, total) = repository.search("", "7", None, None, 0, 10).await.unwrap();
    assert_eq!(total, 1);
    let (rows, total) = repository
        .search("", "pen", None, None, 0, 10)
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(rows[0].model_name, "claude");

    let (_, total) = repository
        .search("", "", Some(0), None, 0, 10)
        .await
        .unwrap();
    assert_eq!(total, 1); // m-zero
    let (_, total) = repository
        .search("", "", None, Some(0), 0, 10)
        .await
        .unwrap();
    // m-zero 与 gpt-beta 都是 sync_official=0。
    assert_eq!(total, 2);

    // 分页：LIMIT/OFFSET。
    let (rows, total) = repository.search("", "", None, None, 1, 2).await.unwrap();
    assert_eq!(total, 5);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].model_name, "claude");

    // ---- 更新：整列覆写含零值；updated_time 刷新 --------------------
    repository
        .update(
            &ModelInput {
                id: Some(42),
                model_name: Some("m-explicit-2".to_owned()),
                status: Some(0),
                ..ModelInput::default()
            },
            now + 5,
        )
        .await
        .unwrap();
    let (_, name, status, _, updated_time) = model_row(db, 42).await;
    assert_eq!(name, "m-explicit-2");
    assert_eq!(status, 0);
    assert_eq!(updated_time, now + 5);

    // 行不存在也是 0 行成功（Go `Updates` 无错）。
    repository
        .update(
            &ModelInput {
                id: Some(9999),
                model_name: Some("ghost".to_owned()),
                ..ModelInput::default()
            },
            now,
        )
        .await
        .unwrap();

    // ---- status_only：只改 status，不触碰 updated_time --------------
    repository.update_status(42, 1).await.unwrap();
    let (_, _, status, _, updated_time) = model_row(db, 42).await;
    assert_eq!(status, 1);
    assert_eq!(updated_time, now + 5);

    // ---- 删除：软删除后不可见 --------------------------------------
    assert!(repository.soft_delete(42, now + 9).await.unwrap());
    assert!(repository.by_id(42).await.unwrap().is_none());
    assert!(!repository.soft_delete(42, now).await.unwrap());

    // ---- vendor_counts：含 0 组，按 vendor_id 升序 ------------------
    let counts = repository.vendor_counts().await.unwrap();
    // 存活行：m-zero/gpt-alpha/gpt-beta（vendor 0）+ claude（vendor 7）。
    assert_eq!(counts, vec![(0, 3), (7, 1)]);

    // ---- 绑定渠道聚合 ----------------------------------------------
    seed_channel(db, 10, "ch-a", 1).await;
    seed_channel(db, 11, "ch-b", 14).await;
    seed_ability(db, "default", "gpt-alpha", 10, true).await;
    seed_ability(db, "vip", "gpt-alpha", 11, true).await;
    seed_ability(db, "default", "disabled-model", 10, false).await;
    let map = repository
        .bound_channels_by_models(&["gpt-alpha".to_owned(), "unknown".to_owned()])
        .await
        .unwrap();
    assert_eq!(
        map.get("gpt-alpha").unwrap(),
        &vec![
            BoundChannel {
                name: "ch-a".to_owned(),
                channel_type: 1,
            },
            BoundChannel {
                name: "ch-b".to_owned(),
                channel_type: 14,
            },
        ]
    );
    assert!(!map.contains_key("unknown"));
    let empty = repository.bound_channels_by_models(&[]).await.unwrap();
    assert!(empty.is_empty());

    // ---- 缺失模型：abilities 启用模型减 models 表 -------------------
    seed_ability(db, "default", "abilities-only", 10, true).await;
    let enabled = abilities::enabled_models(db).await.unwrap();
    assert_eq!(
        enabled,
        vec!["abilities-only".to_owned(), "gpt-alpha".to_owned()]
    );
    let missing = repository.missing_models(&enabled).await.unwrap();
    assert_eq!(missing, vec!["abilities-only".to_owned()]);

    // ---- 供应商：按名查询与补建 ------------------------------------
    assert_eq!(
        repository.vendor_id_by_name("OpenAI").await.unwrap(),
        Some(7)
    );
    assert_eq!(repository.vendor_id_by_name("nope").await.unwrap(), None);
    let vendor_id = repository
        .insert_vendor("Anthropic", "desc", "icon-name", 1, now)
        .await
        .unwrap();
    assert_eq!(
        repository.vendor_id_by_name("Anthropic").await.unwrap(),
        Some(vendor_id)
    );

    // ---- save_all：全列覆写、updated_time 不刷新（Go tx.Save）------
    let mut local = repository.by_name("gpt-beta").await.unwrap().unwrap();
    local.description = "from upstream".to_owned();
    local.status = 2;
    repository.save_all(&local).await.unwrap();
    let (_, _, status, _, updated_time) = model_row(db, 3).await;
    assert_eq!(status, 2);
    assert_eq!(updated_time, 0); // 种入行的 updated_time 保持原值

    // ---- by_names_syncable：sync_official <> 0 过滤 -----------------
    let locals = repository
        .by_names_syncable(&["gpt-alpha".to_owned(), "gpt-beta".to_owned()])
        .await
        .unwrap();
    // gpt-beta 被 save_all 保留 sync_official=0；gpt-alpha 是 1。
    assert_eq!(locals.len(), 1);
    assert_eq!(locals[0].model_name, "gpt-alpha");
    let empty = repository.by_names_syncable(&[]).await.unwrap();
    assert!(empty.is_empty());

    // ---- vendor_names_by_ids --------------------------------------
    let names: BTreeMap<i64, String> = repository
        .vendor_names_by_ids(&[7, vendor_id, 999])
        .await
        .unwrap();
    assert_eq!(names.get(&7).map(String::as_str), Some("OpenAI"));
    assert_eq!(names.get(&vendor_id).map(String::as_str), Some("Anthropic"));
    assert!(!names.contains_key(&999));
    assert!(
        repository
            .vendor_names_by_ids(&[])
            .await
            .unwrap()
            .is_empty()
    );
}
