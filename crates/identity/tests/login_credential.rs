//! 真实数据库契约测试；合成 DDL 不代表生产 schema 或生产 collation。
use newapi_identity::users::LoginCredentialRepository;
use newapi_storage::Database;
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const FIXTURE_HASH: &str = "synthetic-prehashed-login-fixture";
const USERS: &str = "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, status INTEGER NOT NULL, auth_version BIGINT NOT NULL, deleted_at TIMESTAMP)";
const INSERT: &str = "INSERT INTO users (id,username,password,status,auth_version) VALUES ($1,$2,$3,$4,$5)";

// 只输出固定操作标签，禁止输出凭据、DSN 或 SQLx 原始错误。
fn checked<T>(result: Result<T, sqlx::Error>, action: &'static str) -> T {
    result.unwrap_or_else(|_| panic!("login credential fixture failed: {action}"))
}

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

async fn execute(db: &Database, statement: &'static str) {
    backend!(db, pool, {
        checked(
            sqlx::query(statement).execute(pool).await,
            "execute fixed SQL",
        );
    });
}

async fn seed(db: &Database, id: i64, username: &str) {
    backend!(db, pool, {
        checked(
            sqlx::query(INSERT)
                .bind(id)
                .bind(username)
                .bind(FIXTURE_HASH)
                .bind(2_i64)
                .bind(4_294_967_299_i64)
                .execute(pool)
                .await,
            "seed credential",
        );
    });
}

async fn scenarios(db: &Database) {
    let repo = LoginCredentialRepository::new(db.clone());
    execute(db, USERS).await;
    seed(db, 17, "CaseUser").await;
    seed(db, 18, "caseuser").await;
    seed(db, 19, "用户' OR 1=1 --").await;
    seed(db, 20, " CaseUser ").await;

    // 仅声明默认 TEXT fixture 的大小写行为，不覆盖或推断生产库 collation。
    for (username, id) in [
        ("CaseUser", 17),
        ("caseuser", 18),
        ("用户' OR 1=1 --", 19),
        (" CaseUser ", 20),
    ] {
        let credential = checked(repo.by_username(username).await, "read credential")
            .expect("fixture credential must exist");
        assert_eq!(credential.user_id, id);
        assert_eq!(credential.username, username);
        assert_eq!(credential.status, 2, "repository must not filter status");
        assert_eq!(credential.auth_version, 4_294_967_299);
        // 布尔断言不在失败时打印密码的任一操作数。
        assert!(credential.password_hash == FIXTURE_HASH, "hash mismatch");
    }
    for username in ["CASEUSER", "absent", "", "' OR 1=1 --", "CaseUser "] {
        assert!(
            checked(repo.by_username(username).await, "read absent username").is_none()
        );
    }

    execute(
        db,
        "UPDATE users SET deleted_at='2026-01-01 00:00:00' WHERE id=17",
    )
    .await;
    assert!(checked(repo.by_username("CaseUser").await, "read deleted user").is_none());
    assert!(checked(repo.by_username("caseuser").await, "read remaining user").is_some());

    // 每个投影列及软删除条件列缺失都必须传播错误，不能伪装成 None。
    // 仅固定 SQL；每轮重新建表，不依赖恢复旧 prepared statement 的行为。
    for statement in [
        "ALTER TABLE users RENAME COLUMN id TO missing_id",
        "ALTER TABLE users RENAME COLUMN username TO missing_username",
        "ALTER TABLE users RENAME COLUMN password TO missing_password",
        "ALTER TABLE users RENAME COLUMN status TO missing_status",
        "ALTER TABLE users RENAME COLUMN auth_version TO missing_auth_version",
        "ALTER TABLE users RENAME COLUMN deleted_at TO missing_deleted_at",
    ] {
        execute(db, statement).await;
        assert!(repo.by_username("caseuser").await.is_err());
        assert!(repo.by_username("absent").await.is_err());
        execute(db, "DROP TABLE users").await;
        execute(db, USERS).await;
        seed(db, 18, "caseuser").await;
    }
}

async fn assert_closed(db: &Database) {
    db.close().await;
    let repo = LoginCredentialRepository::new(db.clone());
    for username in ["caseuser", "absent"] {
        assert!(matches!(
            repo.by_username(username).await,
            Err(sqlx::Error::PoolClosed)
        ));
    }
}

#[tokio::test]
async fn sqlite_login_credential_contract() {
    // 单连接真实 SQLite 内存库，不使用 mock，也不创建本地持久文件。
    let options = SqliteConnectOptions::new()
        .in_memory(true)
        .disable_statement_logging();
    let pool = checked(
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await,
        "connect SQLite fixture",
    );
    let db = Database::Sqlite(pool);
    scenarios(&db).await;
    assert_closed(&db).await;
}

#[tokio::test]
async fn postgres_login_credential_contract() {
    let dsn = std::env::var("TEST_POSTGRES_DSN")
        .expect("TEST_POSTGRES_DSN required; PostgreSQL must not be skipped");
    let options: PgConnectOptions = dsn
        .parse()
        .unwrap_or_else(|_| panic!("invalid PostgreSQL fixture config"));
    let options = options.disable_statement_logging();
    let admin = checked(
        PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone())
            .await,
        "connect PostgreSQL fixture",
    );
    let schema = format!(
        "login_credential_fixture_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    // DDL 标识符无法绑定；只拼接固定前缀及进程生成的数字，不接受外部输入。
    assert!(
        schema
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    let mut create = sqlx::QueryBuilder::new("CREATE SCHEMA \"");
    create.push(&schema).push("\"");
    checked(
        create.build().execute(&admin).await,
        "create isolated schema",
    );
    let search_path = schema.clone();
    let pool = checked(
        PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |conn, _| {
                let path = search_path.clone();
                Box::pin(async move {
                    sqlx::query::<sqlx::Postgres>("SELECT set_config('search_path', $1, false)")
                        .bind(path)
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await,
        "connect isolated PostgreSQL pool",
    );
    let db = Database::Postgres(pool);
    scenarios(&db).await;
    assert_closed(&db).await;
    let mut drop_schema = sqlx::QueryBuilder::new("DROP SCHEMA \"");
    drop_schema.push(&schema).push("\" CASCADE");
    checked(
        drop_schema.build().execute(&admin).await,
        "drop isolated schema",
    );
    admin.close().await;
}
