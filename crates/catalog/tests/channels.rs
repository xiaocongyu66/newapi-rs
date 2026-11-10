//! 渠道基础 CRUD 仓储的双后端契约（SQLite 内存 + 独立 PostgreSQL schema）。
//!
//! 只跑真实 sqlx 后端；PG 变体在 `TEST_POSTGRES_DSN` 缺失时跳过（P1 CI
//! 注入该变量）。断言对齐 Go `catalog/store_channel.go` 与
//! `store_ability.go` 的可观察行为：过滤谓词、排序、分页、标签聚合、
//! 创建时 abilities 笛卡尔积、按非零字段更新、删除联动。

use newapi_catalog::channels::{
    self, CHANNEL_STATUS_AUTO_DISABLED, CHANNEL_STATUS_ENABLED, CHANNEL_STATUS_MANUALLY_DISABLED,
    ChannelInfo, ChannelListFilter, ChannelRepository, NewChannel, StatusFilter,
};
use newapi_storage::Database;
use sqlx::{
    ConnectOptions,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

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
            execute(db, CHANNELS_SQLITE).await;
            execute(db, ABILITIES_SQLITE).await;
        }
        Database::Postgres(_) => {
            execute(db, CHANNELS_POSTGRES).await;
            execute(db, ABILITIES_POSTGRES).await;
        }
    }
}

async fn reset(db: &Database) {
    execute(db, "DELETE FROM abilities").await;
    execute(db, "DELETE FROM channels").await;
}

/// 直接以 SQL 种入一行渠道（绕过仓储，制造任意状态）。
struct SeedChannel<'a> {
    id: i64,
    channel_type: i64,
    status: i64,
    name: &'a str,
    key: &'a str,
    models: &'a str,
    group: &'a str,
    tag: Option<&'a str>,
}

async fn seed_channel(db: &Database, seed: &SeedChannel<'_>) {
    let info = serde_json::to_string(&ChannelInfo::default()).unwrap();
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                r#"INSERT INTO channels
                    (id, "type", "key", status, name, models, "group", tag,
                     channel_info, settings, other, other_info, base_url,
                     status_code_mapping, balance)
                    VALUES (?,?,?,?,?,?,?,?,?,'','','','','',0)"#,
            )
            .bind(seed.id)
            .bind(seed.channel_type)
            .bind(seed.key)
            .bind(seed.status)
            .bind(seed.name)
            .bind(seed.models)
            .bind(seed.group)
            .bind(seed.tag)
            .bind(&info)
            .execute(pool)
            .await
            .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(
                r#"INSERT INTO channels
                    (id, "type", "key", status, name, models, "group", tag,
                     channel_info, settings, other, other_info, base_url,
                     status_code_mapping, balance)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'','','','','',0)"#,
            )
            .bind(seed.id)
            .bind(seed.channel_type)
            .bind(seed.key)
            .bind(seed.status)
            .bind(seed.name)
            .bind(seed.models)
            .bind(seed.group)
            .bind(seed.tag)
            .bind(&info)
            .execute(pool)
            .await
            .unwrap();
        }
    }
}

async fn ability_count(db: &Database, channel_id: i64) -> i64 {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abilities WHERE channel_id = ?")
                .bind(channel_id)
                .fetch_one(pool)
                .await
                .unwrap()
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abilities WHERE channel_id = $1")
                .bind(channel_id)
                .fetch_one(pool)
                .await
                .unwrap()
        }
    }
}

async fn enabled_ability_count(db: &Database, channel_id: i64) -> i64 {
    match db {
        Database::Sqlite(pool) => sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM abilities WHERE channel_id = ? AND enabled = ?",
        )
        .bind(channel_id)
        .bind(true)
        .fetch_one(pool)
        .await
        .unwrap(),
        Database::Postgres(pool) => sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM abilities WHERE channel_id = $1 AND enabled = $2",
        )
        .bind(channel_id)
        .bind(true)
        .fetch_one(pool)
        .await
        .unwrap(),
    }
}

fn new_channel(
    channel_type: i64,
    key: &str,
    status: i64,
    name: &str,
    models: &str,
    group: &str,
) -> NewChannel {
    NewChannel {
        channel_type,
        key: key.to_owned(),
        openai_organization: None,
        test_model: None,
        status,
        name: name.to_owned(),
        created_time: 1_700_000_000,
        base_url: String::new(),
        other: String::new(),
        models: models.to_owned(),
        group: group.to_owned(),
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
    create_schema(db).await;
    reset(db).await;
    let repository = ChannelRepository::new(db.clone());

    // ---- 创建：abilities 的模型×分组笛卡尔积 --------------------------
    let created = vec![new_channel(
        1,
        "sk-one",
        CHANNEL_STATUS_ENABLED,
        "c-one",
        "m1,m2",
        "default,vip",
    )];
    repository.insert_channels(created).await.unwrap();
    let inserted = repository.by_id(1, true).await.unwrap().unwrap();
    assert_eq!(inserted.name, "c-one");
    assert_eq!(inserted.key, "sk-one");
    // status 缺省（0）经列默认解析为启用：能力行 enabled。
    assert_eq!(ability_count(db, 1).await, 4);
    assert_eq!(enabled_ability_count(db, 1).await, 4);
    // 模型与分组都按 `,` 切分去重（“m1,m1” 不产生重复行）。
    repository
        .insert_channels(vec![new_channel(
            1,
            "sk-dup",
            CHANNEL_STATUS_ENABLED,
            "c-dup",
            "m1,m1",
            "a,a",
        )])
        .await
        .unwrap();
    assert_eq!(ability_count(db, 2).await, 1);
    // 禁用渠道的能力行 enabled=false。
    repository
        .insert_channels(vec![new_channel(
            1,
            "sk-off",
            CHANNEL_STATUS_MANUALLY_DISABLED,
            "c-off",
            "m1",
            "default",
        )])
        .await
        .unwrap();
    assert_eq!(enabled_ability_count(db, 3).await, 0);

    // ---- 列表：过滤 / 排序 / 分页 / 标签 -------------------------------
    seed_channel(
        db,
        &SeedChannel {
            id: 10,
            channel_type: 1,
            status: CHANNEL_STATUS_ENABLED,
            name: "list-a",
            key: "k",
            models: "m1",
            group: "default,vip",
            tag: Some("beta"),
        },
    )
    .await;
    seed_channel(
        db,
        &SeedChannel {
            id: 11,
            channel_type: 41,
            status: CHANNEL_STATUS_ENABLED,
            name: "list-b",
            key: "k",
            models: "m1",
            group: "default",
            tag: Some("alpha"),
        },
    )
    .await;
    seed_channel(
        db,
        &SeedChannel {
            id: 12,
            channel_type: 1,
            status: CHANNEL_STATUS_AUTO_DISABLED,
            name: "list-c",
            key: "k",
            models: "m1",
            group: "default",
            tag: Some("alpha"),
        },
    )
    .await;
    seed_channel(
        db,
        &SeedChannel {
            id: 13,
            channel_type: 1,
            status: CHANNEL_STATUS_ENABLED,
            name: "list-d",
            key: "k",
            models: "m1",
            group: "vip",
            tag: None,
        },
    )
    .await;
    seed_channel(
        db,
        &SeedChannel {
            id: 14,
            channel_type: 1,
            status: CHANNEL_STATUS_ENABLED,
            name: "list-e",
            key: "k",
            models: "m1",
            group: "unrelated",
            tag: Some("beta"),
        },
    )
    .await;

    let all = repository
        .list(
            &ChannelListFilter::default(),
            channels::ChannelSort::IdAsc,
            0,
            100,
        )
        .await
        .unwrap();
    assert_eq!(all.len(), 8);
    // 列表路径不读 key 列（Go Omit("key")）。
    assert!(all.iter().all(|row| row.key.is_empty()));

    let enabled = repository
        .list(
            &ChannelListFilter {
                status: StatusFilter::Enabled,
                ..ChannelListFilter::default()
            },
            channels::ChannelSort::IdAsc,
            0,
            100,
        )
        .await
        .unwrap();
    assert_eq!(enabled.len(), 6);

    let disabled = repository
        .list(
            &ChannelListFilter {
                status: StatusFilter::Disabled,
                ..ChannelListFilter::default()
            },
            channels::ChannelSort::IdAsc,
            0,
            100,
        )
        .await
        .unwrap();
    // c-off（手动禁用）与 list-c（自动禁用）都算禁用。
    assert_eq!(disabled.len(), 2);

    let typed = repository
        .list(
            &ChannelListFilter {
                channel_type: Some(41),
                ..ChannelListFilter::default()
            },
            channels::ChannelSort::IdAsc,
            0,
            100,
        )
        .await
        .unwrap();
    assert_eq!(typed.len(), 1);
    assert_eq!(typed[0].id, 11);

    let group = repository
        .list(
            &ChannelListFilter {
                group: channels::store::normalize_group_filter("vip"),
                ..ChannelListFilter::default()
            },
            channels::ChannelSort::IdAsc,
            0,
            100,
        )
        .await
        .unwrap();
    // default,vip 命中 vip；"vip" 单独分组命中；unrelated 不命中。
    assert!(group.iter().any(|row| row.id == 10));
    assert!(group.iter().any(|row| row.id == 13));
    assert!(!group.iter().any(|row| row.id == 14));

    // 分页位置与总数。
    let page = repository
        .list(
            &ChannelListFilter::default(),
            channels::ChannelSort::IdAsc,
            2,
            2,
        )
        .await
        .unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].id, 3);
    assert_eq!(
        repository
            .count(&ChannelListFilter::default())
            .await
            .unwrap(),
        8
    );

    // type_counts 不含 type 过滤。
    let counts = repository
        .type_counts(&None, StatusFilter::All)
        .await
        .unwrap();
    assert_eq!(counts, vec![(1, 7), (41, 1)]);

    // ---- 标签聚合 ------------------------------------------------------
    let tags = repository
        .tags(
            &ChannelListFilter {
                channel_type: Some(1),
                ..ChannelListFilter::default()
            },
            0,
            100,
        )
        .await
        .unwrap();
    assert_eq!(tags, vec!["alpha".to_owned(), "beta".to_owned()]);
    assert_eq!(
        repository
            .count_tags(&ChannelListFilter {
                channel_type: Some(1),
                ..ChannelListFilter::default()
            })
            .await
            .unwrap(),
        2
    );
    let beta = repository
        .list_by_tag(
            &ChannelListFilter::default(),
            "beta",
            channels::ChannelSort::IdAsc,
        )
        .await
        .unwrap();
    assert!(beta.iter().any(|row| row.id == 10));
    assert!(beta.iter().any(|row| row.id == 14));

    // ---- 搜索 ----------------------------------------------------------
    let by_name = repository
        .search("list-b", &None, "", channels::ChannelSort::IdDesc)
        .await
        .unwrap();
    assert_eq!(by_name.len(), 1);
    assert_eq!(by_name[0].id, 11);
    // 空关键词匹配全部（`name LIKE '%%'`）。
    assert_eq!(
        repository
            .search("", &None, "", channels::ChannelSort::IdDesc)
            .await
            .unwrap()
            .len(),
        8
    );
    // 按 model 过滤 + 分组过滤。
    let model_vip = repository
        .search(
            "",
            &channels::store::normalize_group_filter("vip"),
            "m1",
            channels::ChannelSort::IdDesc,
        )
        .await
        .unwrap();
    assert!(model_vip.iter().any(|row| row.id == 10));
    assert!(model_vip.iter().any(|row| row.id == 13));
    assert!(!model_vip.iter().any(|row| row.id == 12));
    // 搜索标签。
    let search_tags = repository.search_tags("list-b", &None, "").await.unwrap();
    assert_eq!(search_tags, vec!["alpha".to_owned()]);

    // ---- 更新：非零字段 + abilities 重建 -------------------------------
    let patch = channels::ChannelPatch {
        name: Some("c-one-renamed".to_owned()),
        models: Some("m1,m3".to_owned()),
        group: Some("default".to_owned()),
        ..channels::ChannelPatch::default()
    };
    let updated = repository.update(1, &patch, None).await.unwrap().unwrap();
    assert_eq!(updated.name, "c-one-renamed");
    assert_eq!(updated.models, "m1,m3");
    assert_eq!(updated.key, "sk-one");
    // 只 name/models/group 变了，key/base_url 保持。
    assert_eq!(ability_count(db, 1).await, 2);
    assert_eq!(enabled_ability_count(db, 1).await, 2);

    // 空串字段不写（GORM 的零值跳过）。
    let patch = channels::ChannelPatch {
        name: Some(String::new()),
        ..channels::ChannelPatch::default()
    };
    let updated = repository.update(1, &patch, None).await.unwrap().unwrap();
    assert_eq!(updated.name, "c-one-renamed");

    // 模型级隔离在重建时保留（enabled=false 行不被复活）。
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("UPDATE abilities SET enabled = ? WHERE channel_id = ? AND model = ?")
                .bind(false)
                .bind(1)
                .bind("m3")
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("UPDATE abilities SET enabled = $1 WHERE channel_id = $2 AND model = $3")
                .bind(false)
                .bind(1)
                .bind("m3")
                .execute(pool)
                .await
                .unwrap();
        }
    }
    let patch = channels::ChannelPatch {
        models: Some("m1,m3".to_owned()),
        ..channels::ChannelPatch::default()
    };
    repository.update(1, &patch, None).await.unwrap();
    let isolated: Vec<(String, bool)> = match db {
        Database::Sqlite(pool) => {
            sqlx::query("SELECT model, enabled FROM abilities WHERE channel_id = ?")
                .bind(1)
                .fetch_all(pool)
                .await
                .unwrap()
                .into_iter()
                .map(|row| {
                    let model: String = sqlx::Row::try_get(&row, "model").unwrap();
                    let enabled: bool = sqlx::Row::try_get(&row, "enabled").unwrap();
                    (model, enabled)
                })
                .collect()
        }
        Database::Postgres(pool) => {
            sqlx::query("SELECT model, enabled FROM abilities WHERE channel_id = $1")
                .bind(1)
                .fetch_all(pool)
                .await
                .unwrap()
                .into_iter()
                .map(|row| {
                    let model: String = sqlx::Row::try_get(&row, "model").unwrap();
                    let enabled: bool = sqlx::Row::try_get(&row, "enabled").unwrap();
                    (model, enabled)
                })
                .collect()
        }
    };
    let m1 = isolated.iter().find(|(model, _)| model == "m1").unwrap();
    let m3 = isolated.iter().find(|(model, _)| model == "m3").unwrap();
    assert!(m1.1);
    assert!(!m3.1);

    // 更新不存在的 id 回滚并返回 None。
    let missing = repository
        .update(
            999,
            &channels::ChannelPatch {
                name: Some("nope".to_owned()),
                ..channels::ChannelPatch::default()
            },
            None,
        )
        .await
        .unwrap();
    assert!(missing.is_none());

    // ---- 删除 ----------------------------------------------------------
    repository.delete_by_id(1).await.unwrap();
    assert!(repository.by_id(1, true).await.unwrap().is_none());
    assert_eq!(ability_count(db, 1).await, 0);

    // 删除已禁用：只删 status 2/3。
    assert_eq!(repository.delete_by_ids(&[10, 11]).await.unwrap(), 2);
    assert_eq!(ability_count(db, 10).await, 0);
    assert_eq!(repository.delete_disabled().await.unwrap(), 2);
    let remaining = repository
        .list(
            &ChannelListFilter::default(),
            channels::ChannelSort::IdAsc,
            0,
            100,
        )
        .await
        .unwrap();
    assert_eq!(remaining.len(), 4);
}

#[tokio::test]
async fn sqlite_channel_store_contract() {
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
async fn postgres_channel_store_contract() {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return;
    };
    let options: sqlx::postgres::PgConnectOptions = dsn.parse().unwrap();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone().disable_statement_logging())
        .await
        .unwrap();
    let schema = format!("channels_store_{}", std::process::id());
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
