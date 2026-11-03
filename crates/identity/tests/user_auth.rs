//! 仅交远程测试环境执行；隔离合成 DDL 不是生产迁移。
use newapi_identity::user_auth::{
    CredentialKind, PersonalAccessTokenRepository, UserAuthError, UserAuthIdentity, authorize,
};
use newapi_storage::Database;
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

// 不打印 SQLx 原始错误、凭证、hash 或连接配置，包括断言失败路径。
fn checked<T>(result: Result<T, sqlx::Error>, action: &'static str) -> T {
    result.unwrap_or_else(|_| panic!("user_auth fixture failed: {action}"))
}

async fn execute(db: &Database, statement: &str) {
    backend!(db, pool, {
        checked(sqlx::query(statement).execute(pool).await, "execute fixture SQL");
    });
}

// id 允许 NULL，刻意覆盖主键损坏的失败关闭路径；整数保持 Go 旧 PG 列宽。
const USERS: &str = r#"CREATE TABLE users (
    id INTEGER, username TEXT, role INTEGER, status INTEGER,
    auth_version INTEGER, "group" TEXT, access_token TEXT, deleted_at TIMESTAMP
)"#;

fn identity() -> UserAuthIdentity {
    UserAuthIdentity {
        user_id: 17,
        username: " 原样用户 ".into(),
        role: 10,
        status: 1,
        auth_version: 7,
        group: " 原样组 ".into(),
        credential: CredentialKind::PersonalAccessToken,
    }
}

async fn seed(db: &Database, token: Option<&str>) {
    backend!(db, pool, {
        checked(
            sqlx::query(
                r#"INSERT INTO users (id,username,role,status,auth_version,"group",access_token)
                VALUES (17,$1,10,1,7,$2,$3)"#,
            )
            .bind(" 原样用户 ")
            .bind(" 原样组 ")
            .bind(token)
            .execute(pool)
            .await,
            "seed user",
        );
    });
}

async fn scenarios(db: &Database) {
    let repo = PersonalAccessTokenRepository::new(db.clone());
    assert!(repo.by_token("absent").await.is_err());
    execute(db, USERS).await;
    for raw in ["", "absent", "a.b.c", "' OR 1=1 --"] {
        assert!(checked(repo.by_token(raw).await, "empty lookup").is_none());
    }
    seed(db, None).await;
    assert!(checked(repo.by_token("").await, "anonymous NULL token").is_none());
    execute(db, "DELETE FROM users").await;

    // 长度、base64、点号和空白都不属于仓储的格式规则。
    for raw in ["x", "a.b.c", " 特殊.' OR 1=1 -- ", "", "Bearer raw"] {
        seed(db, Some(raw)).await;
        let auth = checked(repo.by_token(raw).await, "exact token lookup")
            .expect("matched user snapshot");
        assert_eq!(auth, identity());
        assert_eq!(authorize(&auth, 10), Ok(()));
        assert!(checked(repo.by_token(&format!("{raw}!")).await, "changed token").is_none());
        if raw != raw.trim() {
            assert!(checked(repo.by_token(raw.trim()).await, "no trimming").is_none());
        }
        if raw == "a.b.c" {
            assert!(checked(repo.by_token("A.b.c").await, "case sensitive token").is_none());
        }
        execute(db, "DELETE FROM users").await;
    }

    let raw = "synthetic-pat.fixture";
    seed(db, Some(raw)).await;
    execute(db, "UPDATE users SET role=100,status=2,auth_version=8").await;
    let auth = checked(repo.by_token(raw).await, "fresh authoritative snapshot")
        .expect("current user");
    assert_eq!((auth.role, auth.status, auth.auth_version), (100, 2, 8));
    assert_eq!(authorize(&auth, 1), Err(UserAuthError::UserDisabled));
    execute(db, "UPDATE users SET deleted_at=CAST('2026-01-01 00:00:00' AS TIMESTAMP)").await;
    assert!(checked(repo.by_token(raw).await, "soft deleted user").is_none());
    execute(db, "DELETE FROM users").await;

    for column in ["id", "username", "role", "status", "auth_version", "group"] {
        seed(db, Some(raw)).await;
        // 仅从固定白名单构造列名，不插值用户输入。
        execute(db, &format!("UPDATE users SET \"{column}\"=NULL")).await;
        match repo.by_token(raw).await {
            Err(sqlx::Error::ColumnDecode { index, source }) => {
                assert_eq!(index, column);
                assert!(source.downcast_ref::<sqlx::error::UnexpectedNullError>().is_some());
            }
            _ => panic!("required NULL must fail closed with fixed ColumnDecode"),
        }
        // 损坏行不得污染未匹配查找。
        assert!(checked(repo.by_token("unmatched").await, "unmatched corrupt row").is_none());
        execute(db, "DELETE FROM users").await;
    }
    execute(db, "DROP TABLE users").await;
    assert!(repo.by_token(raw).await.is_err(), "storage failure is not absence");
}

#[test]
fn authorize_classification_and_go_order() {
    for credential in [CredentialKind::DashboardSession, CredentialKind::PersonalAccessToken] {
        let mut auth = identity();
        auth.credential = credential;
        for status in [i64::MIN, -1, 0, 2, 3, i64::MAX] {
            auth.status = status;
            auth.role = -1;
            auth.user_id = 0;
            auth.username.clear();
            assert_eq!(authorize(&auth, 1), Err(UserAuthError::UserDisabled));
        }
        auth.status = 1;
        assert_eq!(authorize(&auth, 1), Err(UserAuthError::InsufficientRole));
        auth.role = 100;
        assert_eq!(authorize(&auth, 1), Err(UserAuthError::UserInvalid));
        auth = identity();
        auth.credential = credential;
        for id in [i64::MIN, -1, 0] {
            auth.user_id = id;
            assert_eq!(authorize(&auth, 1), Err(UserAuthError::UserInvalid));
        }
        auth.user_id = 17;
        for username in ["", " \t\r\n", "\u{3000}"] {
            auth.username = username.into();
            assert_eq!(authorize(&auth, 1), Err(UserAuthError::UserInvalid));
        }
        auth.username = " user ".into();
        for role in [2, 9, 11, 99, 101, i64::MAX] {
            auth.role = role;
            assert_eq!(authorize(&auth, 0), Err(UserAuthError::UserInvalid));
        }
        for role in [0, 1, 10, 100] {
            auth.role = role;
            assert_eq!(authorize(&auth, role), Ok(()));
            assert_eq!(authorize(&auth, role + 1), Err(UserAuthError::InsufficientRole));
        }
        auth.role = 1;
        auth.auth_version = 0;
        assert_eq!(authorize(&auth, 1), Ok(()), "no invented session version gate");
    }
    assert_eq!(UserAuthError::from(sqlx::Error::PoolClosed), UserAuthError::Storage);
    assert_ne!(UserAuthError::InvalidCredential, UserAuthError::UserInvalid);
}

#[test]
fn pat_identity_has_no_session_or_secret_fields() {
    // 穷尽解构（不使用 ..）：新增 SID/凭证字段会使此契约无法编译。
    let UserAuthIdentity {
        user_id, username, role, status, auth_version, group, credential,
    } = identity();
    assert_eq!(credential, CredentialKind::PersonalAccessToken);
    assert_eq!((user_id, role, status, auth_version), (17, 10, 1, 7));
    assert!(!username.is_empty() && !group.is_empty());
}

#[tokio::test]
async fn sqlite_user_auth_contract() {
    let path = std::env::temp_dir().join(format!(
        "user_auth_fixture_{}_{}.sqlite",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .disable_statement_logging();
    let pool = checked(
        SqlitePoolOptions::new().max_connections(2).connect_with(options).await,
        "connect SQLite fixture",
    );
    let db = Database::Sqlite(pool);
    scenarios(&db).await;
    db.close().await;
    assert!(matches!(
        PersonalAccessTokenRepository::new(db).by_token("closed").await,
        Err(sqlx::Error::PoolClosed)
    ));
    std::fs::remove_file(path).expect("remove isolated SQLite fixture");
}

#[tokio::test]
async fn postgres_user_auth_contract() {
    let dsn = std::env::var("TEST_POSTGRES_DSN")
        .expect("TEST_POSTGRES_DSN required; PostgreSQL must not be skipped");
    let options: PgConnectOptions = dsn
        .parse()
        .unwrap_or_else(|_| panic!("invalid PostgreSQL fixture config"));
    let options = options.disable_statement_logging();
    let admin = checked(
        PgPoolOptions::new().max_connections(1).connect_with(options.clone()).await,
        "connect PostgreSQL fixture",
    );
    let schema = format!(
        "user_auth_fixture_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    assert!(schema.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'));
    checked(
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\"")).execute(&admin).await,
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
        PersonalAccessTokenRepository::new(db).by_token("closed").await,
        Err(sqlx::Error::PoolClosed)
    ));
    checked(
        sqlx::query(&format!("DROP SCHEMA \"{schema}\" CASCADE")).execute(&admin).await,
        "drop isolated schema",
    );
    admin.close().await;
}
