//! 仅由 Actions 执行；这里的 DDL 是隔离合成 fixture，绝非生产迁移器。
//! 非初始化表仅验证列存在门禁，不冒充独立导出的完整 Go schema 金标准。
//!
//! SQLx 0.9 的 query 不接受普通动态字符串，因此动态语句经 QueryBuilder 拼接；
//! 标识符只来自本文件常量、`REQUIRED_SCHEMA_COLUMNS` 或进程内生成的 schema 名，
//! 不接收外部输入，也不使用豁免审计的包装。

use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use newapi_identity::{
    setup::{CompleteSetup, REQUIRED_SCHEMA_COLUMNS, SetupError, SetupRepository},
    users::RootDraft,
};
use newapi_storage::Database;
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

// 合成凭据仅用于证明仓储不再次散列；密码算法由另一切片测试。
const FIXTURE_HASH: &str = "fixture-prehashed-password-not-for-authentication";

// 以下 DDL 均为固定测试常量；不拼接任何运行期标识符。
const SQLITE_USERS_TABLE: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE, password TEXT NOT NULL,
    display_name TEXT, role INTEGER DEFAULT 1, status INTEGER DEFAULT 1,
    email TEXT, github_id TEXT, discord_id TEXT, oidc_id TEXT,
    wechat_id TEXT, telegram_id TEXT, access_token CHAR(32) UNIQUE,
    quota INTEGER DEFAULT 0, used_quota INTEGER DEFAULT 0,
    request_count INTEGER DEFAULT 0, "group" VARCHAR(64) DEFAULT 'default',
    aff_code VARCHAR(32) UNIQUE, aff_count INTEGER DEFAULT 0,
    aff_quota INTEGER DEFAULT 0, aff_history INTEGER DEFAULT 0,
    inviter_id INTEGER, deleted_at TIMESTAMP, linux_do_id TEXT,
    setting TEXT, remark VARCHAR(255), stripe_customer VARCHAR(64),
    created_at BIGINT, last_login_at BIGINT DEFAULT 0,
    auth_version BIGINT NOT NULL DEFAULT 1
)"#;
const POSTGRES_USERS_TABLE: &str = r#"CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE, password TEXT NOT NULL,
    display_name TEXT, role INTEGER DEFAULT 1, status INTEGER DEFAULT 1,
    email TEXT, github_id TEXT, discord_id TEXT, oidc_id TEXT,
    wechat_id TEXT, telegram_id TEXT, access_token CHAR(32) UNIQUE,
    quota INTEGER DEFAULT 0, used_quota INTEGER DEFAULT 0,
    request_count INTEGER DEFAULT 0, "group" VARCHAR(64) DEFAULT 'default',
    aff_code VARCHAR(32) UNIQUE, aff_count INTEGER DEFAULT 0,
    aff_quota INTEGER DEFAULT 0, aff_history INTEGER DEFAULT 0,
    inviter_id INTEGER, deleted_at TIMESTAMP, linux_do_id TEXT,
    setting TEXT, remark VARCHAR(255), stripe_customer VARCHAR(64),
    created_at BIGINT, last_login_at BIGINT DEFAULT 0,
    auth_version BIGINT NOT NULL DEFAULT 1
)"#;
const SETUPS_TABLE: &str = "CREATE TABLE setups (id BIGINT PRIMARY KEY, version VARCHAR(50) NOT NULL DEFAULT 'legacy-unknown', initialized_at BIGINT NOT NULL DEFAULT 0)";
const OPTIONS_TABLE: &str = "CREATE TABLE options (\"key\" TEXT PRIMARY KEY, value TEXT)";
const MODE_REFUSING_OPTIONS_TABLE: &str = "CREATE TABLE options (\"key\" TEXT PRIMARY KEY, value TEXT, CHECK (\"key\" <> 'DemoSiteEnabled'))";
const MODE_SEED: &str = "INSERT INTO options VALUES ('SelfUseModeEnabled','old')";
const SETUP_REFUSING_PRIMARY_TABLE: &str = "CREATE TABLE setups (id BIGINT PRIMARY KEY, version VARCHAR(50) NOT NULL DEFAULT 'legacy-unknown', initialized_at BIGINT NOT NULL DEFAULT 0, CHECK (id <> 1))";
const SOFT_DELETED_ROOT: &str = "INSERT INTO users(username,password,role,deleted_at,aff_code) VALUES ('管理员','old',100,'2026-01-01 00:00:00','old-aff')";
const LEGACY_SETUP: &str = "INSERT INTO setups(id) VALUES (42)";
const DROP_USER_COLUMN: &str = "ALTER TABLE users RENAME COLUMN aff_history TO wrong_aff_history";
const RESTORE_USER_COLUMN: &str = "ALTER TABLE users RENAME COLUMN wrong_aff_history TO aff_history";
const OPTIONS_WITHOUT_KEY: &str = "CREATE TABLE options (\"key\" TEXT, value TEXT)";
const DROP_OPTIONS: &str = "DROP TABLE options";
const DROP_SETUPS: &str = "DROP TABLE setups";
const CREATE_EMAIL_INDEX: &str = "CREATE INDEX fixture_email ON users (email)";
const DELETE_SETUPS: &str = "DELETE FROM setups";
const COUNT_SETUPS: &str = "SELECT count(*) FROM setups";
const COUNT_USERS: &str = "SELECT count(*) FROM users";
const COUNT_OPTIONS: &str = "SELECT count(*) FROM options";
const ROOT_SETUP_COUNT: &str =
    "SELECT count(*) FROM setups WHERE id = 1 AND initialized_at = 1700000000";
const ROOT_USER_COUNT: &str = "SELECT count(*) FROM users WHERE role = 100 AND status = 1 AND quota = 100000000 AND auth_version = 1 AND access_token IS NULL AND deleted_at IS NULL AND aff_history = 0 AND \"group\" = 'default' AND display_name = 'Root User'";
const USER_PASSWORD: &str = "SELECT password FROM users";
const SELF_USE_MODE: &str = "SELECT value FROM options WHERE \"key\" = 'SelfUseModeEnabled'";
const DEMO_SITE_MODE: &str = "SELECT value FROM options WHERE \"key\" = 'DemoSiteEnabled'";
const FIRST_OPTION_VALUE: &str = "SELECT value FROM options";

/// 测试专用执行：内容仅为固定常量或由固定表列白名单生成的 DDL。
async fn execute(db: &Database, statement: &str) {
    let result = match db {
        Database::Sqlite(pool) => sqlx::QueryBuilder::new("")
            .push(statement)
            .build()
            .execute(pool)
            .await
            .map(|_| ()),
        Database::Postgres(pool) => sqlx::QueryBuilder::new("")
            .push(statement)
            .build()
            .execute(pool)
            .await
            .map(|_| ()),
    };
    assert!(result.is_ok(), "测试数据库语句失败");
}

async fn count(db: &Database, statement: &str) -> i64 {
    match db {
        Database::Sqlite(pool) => sqlx::QueryBuilder::new("")
            .push(statement)
            .build_query_scalar()
            .fetch_one(pool)
            .await,
        Database::Postgres(pool) => sqlx::QueryBuilder::new("")
            .push(statement)
            .build_query_scalar()
            .fetch_one(pool)
            .await,
    }
    .unwrap_or_else(|_| panic!("测试数据库计数失败"))
}

async fn text(db: &Database, statement: &str) -> String {
    match db {
        Database::Sqlite(pool) => sqlx::QueryBuilder::new("")
            .push(statement)
            .build_query_scalar()
            .fetch_one(pool)
            .await,
        Database::Postgres(pool) => sqlx::QueryBuilder::new("")
            .push(statement)
            .build_query_scalar()
            .fetch_one(pool)
            .await,
    }
    .unwrap_or_else(|_| panic!("测试数据库投影失败"))
}

fn input() -> CompleteSetup {
    CompleteSetup {
        root: Some(RootDraft {
            username: "管理员".into(),
            password_hash: FIXTURE_HASH.into(),
        }),
        version: "p2-fixture".into(),
        initialized_at: 1_700_000_000,
        self_use_mode_enabled: true,
        demo_site_enabled: false,
    }
}

async fn core_fixture(db: &Database) {
    match db {
        Database::Sqlite(_) => execute(db, SQLITE_USERS_TABLE).await,
        Database::Postgres(_) => execute(db, POSTGRES_USERS_TABLE).await,
    }
    execute(db, CREATE_EMAIL_INDEX).await;
    execute(db, SETUPS_TABLE).await;
    execute(db, OPTIONS_TABLE).await;
}

async fn remaining_columns_fixture(db: &Database) {
    for &(table, columns) in REQUIRED_SCHEMA_COLUMNS {
        if matches!(table, "users" | "setups" | "options") {
            continue;
        }
        // 表名与列名只来自共享固定白名单常量，不接收外部输入。
        let definitions = columns
            .split(',')
            .map(|column| format!("\"{column}\" TEXT"))
            .collect::<Vec<_>>()
            .join(",");
        execute(db, &format!("CREATE TABLE \"{table}\" ({definitions})")).await;
    }
}

async fn reset_rows(db: &Database) {
    for statement in [DELETE_SETUPS, "DELETE FROM users", "DELETE FROM options"] {
        execute(db, statement).await;
    }
}

async fn scenarios(db: &Database, second: &Database) {
    let repo = SetupRepository::new(db.clone());
    assert_eq!(repo.inspect().await, Err(SetupError::SchemaNotReady));
    assert_eq!(
        repo.complete(input()).await,
        Err(SetupError::SchemaNotReady)
    );
    core_fixture(db).await;
    // 只有三张表必须拒绝，不能用最小 fixture 宣称系统完成。
    assert_eq!(repo.inspect().await, Err(SetupError::SchemaNotReady));
    assert_eq!(
        repo.complete(input()).await,
        Err(SetupError::SchemaNotReady)
    );
    assert_eq!(count(db, COUNT_SETUPS).await, 0);
    remaining_columns_fixture(db).await;
    let initial = repo.inspect().await.expect("读取初始状态");
    assert!(!initial.initialized);
    assert!(!initial.root.exists);
    assert_eq!(count(db, COUNT_USERS).await, 0);

    // 两个独立连接池模拟独立实例，不能依赖仓储对象或进程互斥锁。
    let other = SetupRepository::new(second.clone());
    let (first, second_result) = tokio::join!(repo.complete(input()), other.complete(input()));
    assert_eq!(
        usize::from(first.is_ok()) + usize::from(second_result.is_ok()),
        1
    );
    let loser = if first.is_err() { first } else { second_result };
    assert_eq!(loser, Err(SetupError::AlreadyInitialized));
    assert_eq!(count(db, COUNT_USERS).await, 1);
    assert_eq!(count(db, ROOT_SETUP_COUNT).await, 1);
    assert_eq!(text(db, USER_PASSWORD).await, FIXTURE_HASH);
    assert_eq!(count(db, ROOT_USER_COUNT).await, 1);
    assert_eq!(text(db, SELF_USE_MODE).await, "true");
    assert_eq!(text(db, DEMO_SITE_MODE).await, "false");
    assert!(other.inspect().await.expect("重新读取持久状态").initialized);

    // 无 setup 的旧 root 只能显式确认，inspect 不补写且 complete 不覆盖密码。
    execute(db, DELETE_SETUPS).await;
    assert!(repo.inspect().await.expect("旧管理员状态").root.exists);
    assert_eq!(count(db, COUNT_SETUPS).await, 0);
    let mut confirmation = input();
    confirmation.root = None;
    let completed = repo.complete(confirmation).await.expect("确认旧管理员");
    assert!(!completed.root_created);
    assert_eq!(text(db, USER_PASSWORD).await, FIXTURE_HASH);

    // 任意旧 setup 记录都算已完成，不要求 id=1，不修复或删除旧记录。
    reset_rows(db).await;
    execute(db, LEGACY_SETUP).await;
    assert!(repo.inspect().await.expect("旧初始化状态").initialized);
    assert_eq!(
        repo.complete(input()).await,
        Err(SetupError::AlreadyInitialized)
    );
    assert_eq!(count(db, COUNT_USERS).await, 0);

    // 用户名限制按 UTF-8 字节，且仓储不发明非空用户名规则。
    reset_rows(db).await;
    let mut too_long = input();
    too_long.root.as_mut().expect("测试凭据").username = "五个汉字长".into();
    assert_eq!(repo.complete(too_long).await, Err(SetupError::InvalidInput));
    assert_eq!(count(db, COUNT_USERS).await, 0);
    let mut boundary = input();
    boundary.root.as_mut().expect("测试凭据").username = "四个汉字".into();
    assert!(repo.complete(boundary).await.is_ok());
    reset_rows(db).await;
    let mut empty = input();
    empty.root.as_mut().expect("测试凭据").username.clear();
    assert!(repo.complete(empty).await.is_ok());

    // 软删除 root 不算存在，但用户名唯一性仍保留；失败不得写模式或 setup。
    reset_rows(db).await;
    execute(db, SOFT_DELETED_ROOT).await;
    assert!(!repo.inspect().await.expect("软删除状态").root.exists);
    assert_eq!(
        repo.complete(input()).await,
        Err(SetupError::RootCreationFailed)
    );
    assert_eq!(count(db, COUNT_USERS).await, 1);
    assert_eq!(count(db, COUNT_SETUPS).await, 0);
    assert_eq!(count(db, COUNT_OPTIONS).await, 0);

    // 第二个模式保存失败：root 及第一个模式更新必须全部回滚。
    reset_rows(db).await;
    execute(db, DROP_OPTIONS).await;
    execute(db, MODE_REFUSING_OPTIONS_TABLE).await;
    execute(db, MODE_SEED).await;
    assert_eq!(
        repo.complete(input()).await,
        Err(SetupError::ModeSaveFailed)
    );
    assert_eq!(count(db, COUNT_USERS).await, 0);
    assert_eq!(count(db, COUNT_SETUPS).await, 0);
    assert_eq!(text(db, FIRST_OPTION_VALUE).await, "old");
    execute(db, DROP_OPTIONS).await;
    execute(db, OPTIONS_TABLE).await;

    // 最后一步失败也不能留下 root 或模式，错误不能被吞成已初始化。
    execute(db, DROP_SETUPS).await;
    execute(db, SETUP_REFUSING_PRIMARY_TABLE).await;
    assert_eq!(
        repo.complete(input()).await,
        Err(SetupError::SetupSaveFailed)
    );
    assert_eq!(count(db, COUNT_USERS).await, 0);
    assert_eq!(count(db, COUNT_OPTIONS).await, 0);

    // 缺列和缺唯一性都拒绝，不偷偷迁移。
    execute(db, DROP_USER_COLUMN).await;
    assert_eq!(repo.inspect().await, Err(SetupError::SchemaNotReady));
    execute(db, RESTORE_USER_COLUMN).await;
    execute(db, DROP_OPTIONS).await;
    execute(db, OPTIONS_WITHOUT_KEY).await;
    assert_eq!(repo.inspect().await, Err(SetupError::SchemaNotReady));
    assert_eq!(
        repo.complete(input()).await,
        Err(SetupError::SchemaNotReady)
    );
}

struct Directory(PathBuf);

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn sqlite_setup_repository_contract() {
    let path = std::env::temp_dir().join(format!(
        "newapi-setup-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path).expect("创建隔离测试目录");
    let directory = Directory(path);
    let options = SqliteConnectOptions::new()
        .filename(directory.0.join("fixture.db"))
        .create_if_missing(true)
        .busy_timeout(Duration::from_secs(10))
        .disable_statement_logging();
    let pool = SqlitePoolOptions::new()
        .max_connections(3)
        .connect_with(options.clone())
        .await
        .expect("连接 SQLite fixture");
    let second = SqlitePoolOptions::new()
        .max_connections(3)
        .connect_with(options)
        .await
        .expect("第二个 SQLite 连接池");
    let db = Database::Sqlite(pool);
    let other = Database::Sqlite(second);
    scenarios(&db, &other).await;
    other.close().await;
    db.close().await;
    assert_eq!(
        SetupRepository::new(db).inspect().await,
        Err(SetupError::Unavailable)
    );
}

#[tokio::test]
async fn postgres_setup_repository_contract() {
    let dsn = std::env::var("TEST_POSTGRES_DSN")
        .expect("TEST_POSTGRES_DSN 必须由 Actions 提供，不允许跳过 PostgreSQL 测试");
    let options: PgConnectOptions = dsn
        .parse()
        .unwrap_or_else(|_| panic!("PostgreSQL fixture 配置无效"));
    let options = options.disable_statement_logging();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap_or_else(|_| panic!("PostgreSQL fixture 连接失败"));
    let schema = format!(
        "setup_fixture_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    sqlx::QueryBuilder::new("CREATE SCHEMA \"")
        .push(&schema)
        .push("\"")
        .build()
        .execute(&admin)
        .await
        .expect("创建独立测试 schema");
    let mut pools = Vec::new();
    for _ in 0..2 {
        let search_path = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .after_connect(move |conn, _| {
                let schema = search_path.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('search_path', $1, false)")
                        .bind(schema)
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options.clone())
            .await
            .unwrap_or_else(|_| panic!("隔离 PostgreSQL 连接池失败"));
        pools.push(Database::Postgres(pool));
    }
    scenarios(&pools[0], &pools[1]).await;
    for pool in &pools {
        pool.close().await;
    }
    assert_eq!(
        SetupRepository::new(pools[0].clone()).inspect().await,
        Err(SetupError::Unavailable)
    );
    sqlx::QueryBuilder::new("DROP SCHEMA \"")
        .push(&schema)
        .push("\" CASCADE")
        .build()
        .execute(&admin)
        .await
        .expect("清理独立测试 schema");
    admin.close().await;
}
