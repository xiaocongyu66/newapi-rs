//! 仅交远程测试环境执行；合成隔离 DDL 不是生产迁移或完整 Go schema 金标准。
use newapi_identity::users::{UserProfile, UserProfileRepository};
use newapi_storage::Database;
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

// 分别推导 SQLite/PG 类型；不使用 Any。动态值只允许 push_bind。
macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

// 不在失败日志中输出 SQLx 原始错误、连接配置或资料内容。
fn checked<T>(result: Result<T, sqlx::Error>, action: &'static str) -> T {
    result.unwrap_or_else(|_| panic!("user_profile fixture failed: {action}"))
}

async fn execute(db: &Database, statement: &'static str) {
    backend!(db, pool, {
        checked(
            sqlx::QueryBuilder::new(statement)
                .build()
                .execute(pool)
                .await,
            "execute fixed SQL",
        );
    });
}

// INTEGER 有意保留 Go 旧 PG 列宽，验证生产查询的 BIGINT CAST。
// 机密列填充合成值，不读取真实凭据。
const USERS: &str = r#"CREATE TABLE users (
    id INTEGER PRIMARY KEY, username TEXT, password TEXT NOT NULL,
    display_name TEXT, role INTEGER, status INTEGER, email TEXT,
    github_id TEXT, discord_id TEXT, oidc_id TEXT, wechat_id TEXT, telegram_id TEXT,
    access_token CHAR(32), quota INTEGER, used_quota INTEGER, request_count INTEGER,
    "group" VARCHAR(64), aff_code VARCHAR(32), aff_count INTEGER,
    aff_quota INTEGER, aff_history INTEGER, inviter_id INTEGER,
    deleted_at TIMESTAMP, linux_do_id TEXT, setting TEXT,
    remark VARCHAR(255), stripe_customer VARCHAR(64), created_at BIGINT,
    last_login_at BIGINT, auth_version BIGINT
)"#;

fn expected() -> UserProfile {
    UserProfile {
        id: 17,
        username: "用户' OR 1=1 --".into(),
        display_name: " 原样名称 ".into(),
        role: 10,
        status: 2,
        email: "fixture@example.invalid".into(),
        github_id: "github-fixture".into(),
        discord_id: "discord-fixture".into(),
        oidc_id: "oidc-fixture".into(),
        wechat_id: "wechat-fixture".into(),
        telegram_id: "telegram-fixture".into(),
        group: "非默认组".into(),
        quota: 2_000_000_001,
        used_quota: 1_234_567,
        request_count: 456,
        aff_code: "aff-fixture".into(),
        aff_count: 7,
        aff_quota: -91,
        aff_history_quota: 123_456_789,
        inviter_id: 9,
        linux_do_id: "linux-do-fixture".into(),
        // 不解析 JSON，不派生 sidebar_modules，也不调整额度。
        setting: " {\"sidebar_modules\":\"fixture\",\"unknown\":true} ".into(),
        stripe_customer: "stripe-fixture".into(),
        // seed 写入 auth_version=777；验证列映射而不是默认值。
        auth_version: 777,
    }
}

async fn seed(db: &Database, profile: &UserProfile) {
    backend!(db, pool, {
        let mut insert = sqlx::QueryBuilder::new(
            "INSERT INTO users (id,username,display_name,role,status,email,github_id,discord_id,oidc_id,wechat_id,telegram_id,\"group\",quota,used_quota,request_count,aff_code,aff_count,aff_quota,aff_history,inviter_id,linux_do_id,setting,stripe_customer,password,access_token,remark,auth_version) VALUES (",
        );
        insert
            .push_bind(profile.id)
            .push(",")
            .push_bind(&profile.username)
            .push(",")
            .push_bind(&profile.display_name)
            .push(",")
            .push_bind(profile.role)
            .push(",")
            .push_bind(profile.status)
            .push(",")
            .push_bind(&profile.email)
            .push(",")
            .push_bind(&profile.github_id)
            .push(",")
            .push_bind(&profile.discord_id)
            .push(",")
            .push_bind(&profile.oidc_id)
            .push(",")
            .push_bind(&profile.wechat_id)
            .push(",")
            .push_bind(&profile.telegram_id)
            .push(",")
            .push_bind(&profile.group)
            .push(",")
            .push_bind(profile.quota)
            .push(",")
            .push_bind(profile.used_quota)
            .push(",")
            .push_bind(profile.request_count)
            .push(",")
            .push_bind(&profile.aff_code)
            .push(",")
            .push_bind(profile.aff_count)
            .push(",")
            .push_bind(profile.aff_quota)
            .push(",")
            .push_bind(profile.aff_history_quota)
            .push(",")
            .push_bind(profile.inviter_id)
            .push(",")
            .push_bind(&profile.linux_do_id)
            .push(",")
            .push_bind(&profile.setting)
            .push(",")
            .push_bind(&profile.stripe_customer)
            .push(",")
            .push_bind("synthetic-password-not-for-auth")
            .push(",")
            .push_bind("synthetic-management-token")
            .push(",")
            .push_bind("admin-only-fixture-remark")
            .push(",")
            .push_bind(777_i64)
            .push(")");
        checked(insert.build().execute(pool).await, "seed profile");
    });
}

async fn scenarios(db: &Database) {
    let repo = UserProfileRepository::new(db.clone());
    assert!(repo.by_id(17).await.is_err(), "缺表必须传播错误");
    execute(db, USERS).await;
    let profile = expected();
    seed(db, &profile).await;
    // 完整比较同时验证每个列映射；status=2 仍可读，本仓储不是鉴权层。
    assert_eq!(checked(repo.by_id(17).await, "read profile"), Some(profile));
    for id in [0, -1, 18, i64::MAX] {
        assert!(checked(repo.by_id(id).await, "read absent id").is_none());
    }

    backend!(db, pool, {
        let mut insert = sqlx::QueryBuilder::new("INSERT INTO users (id,password) VALUES (");
        insert
            .push_bind(18_i64)
            .push(",")
            .push_bind("synthetic-legacy")
            .push(")");
        checked(
            insert.build().execute(pool).await,
            "seed nullable legacy row",
        );
    });
    // 所有旧可空列均回到 Go 零值，不能擅自赋 role=1 或 group=default。
    let null_profile = UserProfile {
        id: 18,
        username: String::new(),
        display_name: String::new(),
        role: 0,
        status: 0,
        email: String::new(),
        github_id: String::new(),
        discord_id: String::new(),
        oidc_id: String::new(),
        wechat_id: String::new(),
        telegram_id: String::new(),
        group: String::new(),
        quota: 0,
        used_quota: 0,
        request_count: 0,
        aff_code: String::new(),
        aff_count: 0,
        aff_quota: 0,
        aff_history_quota: 0,
        inviter_id: 0,
        linux_do_id: String::new(),
        setting: String::new(),
        stripe_customer: String::new(),
        auth_version: 0,
    };
    assert_eq!(
        checked(repo.by_id(18).await, "read NULL legacy row"),
        Some(null_profile)
    );

    // 无效 JSON 也保留原文，读取边界不替后续组装层解析设置。
    backend!(db, pool, {
        let mut update = sqlx::QueryBuilder::new("UPDATE users SET setting=");
        update
            .push_bind("not-json")
            .push(" WHERE id=")
            .push_bind(18_i64);
        checked(update.build().execute(pool).await, "update raw setting");
    });
    assert_eq!(
        checked(repo.by_id(18).await, "read raw setting")
            .expect("legacy row")
            .setting,
        "not-json"
    );
    backend!(db, pool, {
        let mut update = sqlx::QueryBuilder::new("UPDATE users SET deleted_at=CAST(");
        update
            .push_bind("2026-01-01 00:00:00")
            .push(" AS TIMESTAMP) WHERE id=")
            .push_bind(17_i64);
        checked(update.build().execute(pool).await, "soft delete profile");
    });
    assert!(checked(repo.by_id(17).await, "read deleted profile").is_none());
    assert!(checked(repo.by_id(18).await, "unrelated row remains").is_some());
    execute(db, "DROP TABLE users").await;
    assert!(repo.by_id(18).await.is_err(), "存储失败不能伪装未找到");
}

#[tokio::test]
async fn sqlite_user_profile_contract() {
    let path = std::env::temp_dir().join(format!(
        "user_profile_fixture_{}_{}.sqlite",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .disable_statement_logging();
    let pool = checked(
        SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await,
        "connect SQLite fixture",
    );
    let db = Database::Sqlite(pool);
    scenarios(&db).await;
    db.close().await;
    assert!(matches!(
        UserProfileRepository::new(db).by_id(17).await,
        Err(sqlx::Error::PoolClosed)
    ));
    std::fs::remove_file(path).expect("remove isolated SQLite fixture");
}

#[tokio::test]
async fn postgres_user_profile_contract() {
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
        "user_profile_fixture_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    // DDL 标识符无法绑定，仅允许固定前缀与进程内生成的数字/下划线。
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
            .max_connections(2)
            .after_connect(move |conn, _| {
                let path = search_path.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('search_path', $1, false)")
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
    db.close().await;
    assert!(matches!(
        UserProfileRepository::new(db).by_id(17).await,
        Err(sqlx::Error::PoolClosed)
    ));
    let mut drop_schema = sqlx::QueryBuilder::new("DROP SCHEMA \"");
    drop_schema.push(&schema).push("\" CASCADE");
    checked(
        drop_schema.build().execute(&admin).await,
        "drop isolated schema",
    );
    admin.close().await;
}
