//! 登录路径 2FA 契约：SQLite 真实内存库 + TEST_POSTGRES_DSN 隔离 schema。
//!
//! 测试向量来源：
//! - RFC 4226 Appendix D：共享密钥 ASCII "12345678901234567890" 的 HOTP 值；
//!   TOTP 的第 N 个时间步与 HOTP counter N 相同。
//! - RFC 6238 Appendix B：SHA1 时间向量（8 位）；6 位码取末 6 位。
//!
//! 本文件不运行迁移器；DDL 只是与 Go GORM 模型列名一致的最小 fixture。

use std::{
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use newapi_identity::{
    crypto::hash_password,
    two_fa::{
        LOCKOUT_SECONDS, MAX_FAIL_ATTEMPTS, TwoFaError, TwoFaRepository,
        totp::normalize_backup_code,
    },
};
use newapi_storage::Database;
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPool, PgPoolOptions},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

// RFC 4226/6238 共享密钥的 base32 编码。
const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

const SQLITE_DDL: &[&str] = &[
    "CREATE TABLE two_fas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        secret VARCHAR(255) NOT NULL,
        is_enabled INTEGER NOT NULL DEFAULT 0,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked_until DATETIME,
        last_used_at DATETIME,
        created_at DATETIME,
        updated_at DATETIME,
        deleted_at DATETIME
    )",
    "CREATE INDEX idx_two_fas_user_id ON two_fas (user_id)",
    "CREATE INDEX idx_two_fas_deleted_at ON two_fas (deleted_at)",
    "CREATE TABLE two_fa_backup_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code_hash VARCHAR(255) NOT NULL,
        is_used INTEGER NOT NULL DEFAULT 0,
        used_at DATETIME,
        created_at DATETIME,
        deleted_at DATETIME
    )",
    "CREATE INDEX idx_two_fa_backup_codes_user_id ON two_fa_backup_codes (user_id)",
    "CREATE INDEX idx_two_fa_backup_codes_deleted_at ON two_fa_backup_codes (deleted_at)",
];

const POSTGRES_DDL: &[&str] = &[
    "CREATE TABLE two_fas (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL UNIQUE,
        secret VARCHAR(255) NOT NULL,
        is_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        failed_attempts BIGINT NOT NULL DEFAULT 0,
        locked_until TIMESTAMPTZ,
        last_used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ,
        updated_at TIMESTAMPTZ,
        deleted_at TIMESTAMPTZ
    )",
    "CREATE INDEX idx_two_fas_user_id ON two_fas (user_id)",
    "CREATE INDEX idx_two_fas_deleted_at ON two_fas (deleted_at)",
    "CREATE TABLE two_fa_backup_codes (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL,
        code_hash VARCHAR(255) NOT NULL,
        is_used BOOLEAN NOT NULL DEFAULT FALSE,
        used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ,
        deleted_at TIMESTAMPTZ
    )",
    "CREATE INDEX idx_two_fa_backup_codes_user_id ON two_fa_backup_codes (user_id)",
    "CREATE INDEX idx_two_fa_backup_codes_deleted_at ON two_fa_backup_codes (deleted_at)",
];

fn sqlite_options() -> SqliteConnectOptions {
    // `sqlite::memory:` 由 SQLx 解析为 in-memory + shared-cache。
    SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("SQLite in-memory DSN must parse")
        .busy_timeout(Duration::from_secs(10))
        .disable_statement_logging()
}

async fn sqlite_database() -> Database {
    // 单连接让 SQLite fixture 不产生 shared-cache 表锁；条件 UPDATE 的唯一赢家
    // 语义仍由两个并发 task 的调用顺序验证，PostgreSQL 用例提供真正并发。
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(sqlite_options())
        .await
        .expect("connect SQLite in-memory fixture");
    for statement in SQLITE_DDL.iter().copied() {
        sqlx::query(statement)
            .execute(&pool)
            .await
            .expect("create SQLite 2FA fixture schema");
    }
    Database::Sqlite(pool)
}

async fn postgres_database(options: &PgConnectOptions) -> (PgPool, Database, String) {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap_or_else(|_| panic!("PostgreSQL fixture connection failed"));
    let schema = format!(
        "two_fa_fixture_{}_{}",
        std::process::id(),
        NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
    );
    let mut statement = sqlx::QueryBuilder::new("CREATE SCHEMA \"");
    statement.push(&schema).push("\"");
    statement
        .build()
        .execute(&admin)
        .await
        .expect("create isolated PostgreSQL schema");

    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .after_connect(move |connection, _| {
            let search_path = search_path.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path', $1, false)")
                    .bind(search_path)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options.clone())
        .await
        .unwrap_or_else(|_| panic!("connect isolated PostgreSQL fixture"));
    for statement in POSTGRES_DDL.iter().copied() {
        sqlx::query(statement)
            .execute(&pool)
            .await
            .expect("create PostgreSQL 2FA fixture schema");
    }
    (admin, Database::Postgres(pool), schema)
}

async fn drop_schema(admin: &PgPool, schema: &str) {
    let mut statement = sqlx::QueryBuilder::new("DROP SCHEMA \"");
    statement.push(schema).push("\" CASCADE");
    statement
        .build()
        .execute(admin)
        .await
        .expect("drop isolated PostgreSQL schema");
}

async fn seed_two_fa(
    database: &Database,
    user_id: i64,
    secret: &str,
    is_enabled: bool,
    failed_attempts: i64,
    locked_until: Option<i64>,
) {
    match database {
        Database::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO two_fas
                    (user_id, secret, is_enabled, failed_attempts, locked_until, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, datetime($5, 'unixepoch'),
                    datetime($6, 'unixepoch'), datetime($6, 'unixepoch'))",
            )
            .bind(user_id)
            .bind(secret)
            .bind(is_enabled)
            .bind(failed_attempts)
            .bind(locked_until)
            .bind(locked_until.unwrap_or(0))
            .execute(pool)
            .await
            .expect("seed SQLite two_fa");
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "INSERT INTO two_fas
                    (user_id, secret, is_enabled, failed_attempts, locked_until, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, to_timestamp($5::BIGINT),
                    to_timestamp($6::BIGINT), to_timestamp($6::BIGINT))",
            )
            .bind(user_id)
            .bind(secret)
            .bind(is_enabled)
            .bind(failed_attempts)
            .bind(locked_until)
            .bind(locked_until.unwrap_or(0))
            .execute(pool)
            .await
            .expect("seed PostgreSQL two_fa");
        }
    }
}

async fn seed_backup_code(database: &Database, user_id: i64, plain: &str, is_used: bool) {
    let normalized = normalize_backup_code(plain).expect("fixture backup code must be valid");
    let code_hash = hash_password(normalized.as_bytes())
        .expect("hash fixture backup code")
        .expose_secret()
        .to_owned();
    match database {
        Database::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO two_fa_backup_codes (user_id, code_hash, is_used)
                 VALUES ($1, $2, $3)",
            )
            .bind(user_id)
            .bind(code_hash)
            .bind(is_used)
            .execute(pool)
            .await
            .expect("seed SQLite backup code");
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "INSERT INTO two_fa_backup_codes (user_id, code_hash, is_used)
                 VALUES ($1, $2, $3)",
            )
            .bind(user_id)
            .bind(code_hash)
            .bind(is_used)
            .execute(pool)
            .await
            .expect("seed PostgreSQL backup code");
        }
    }
}

/// 返回 `(failed_attempts, locked_until_epoch, last_used_at_epoch)`。
async fn read_attempts(database: &Database, user_id: i64) -> (i64, Option<i64>, Option<i64>) {
    match database {
        Database::Sqlite(pool) => sqlx::query_as::<_, (i64, Option<i64>, Option<i64>)>(
            "SELECT failed_attempts,
                CASE WHEN locked_until IS NULL THEN NULL
                     ELSE CAST(strftime('%s', locked_until) AS INTEGER) END,
                CASE WHEN last_used_at IS NULL THEN NULL
                     ELSE CAST(strftime('%s', last_used_at) AS INTEGER) END
             FROM two_fas WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("read SQLite two_fa state"),
        Database::Postgres(pool) => sqlx::query_as::<_, (i64, Option<i64>, Option<i64>)>(
            "SELECT failed_attempts,
                CASE WHEN locked_until IS NULL THEN NULL
                     ELSE CAST(EXTRACT(EPOCH FROM locked_until) AS BIGINT) END,
                CASE WHEN last_used_at IS NULL THEN NULL
                     ELSE CAST(EXTRACT(EPOCH FROM last_used_at) AS BIGINT) END
             FROM two_fas WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("read PostgreSQL two_fa state"),
    }
}

async fn used_backup_code_count(database: &Database, user_id: i64) -> i64 {
    match database {
        Database::Sqlite(pool) => sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM two_fa_backup_codes WHERE user_id = $1 AND is_used = $2",
        )
        .bind(user_id)
        .bind(true)
        .fetch_one(pool)
        .await
        .expect("count used SQLite backup codes"),
        Database::Postgres(pool) => sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM two_fa_backup_codes WHERE user_id = $1 AND is_used = $2",
        )
        .bind(user_id)
        .bind(true)
        .fetch_one(pool)
        .await
        .expect("count used PostgreSQL backup codes"),
    }
}

async fn totp_window(database: &Database) {
    let repo = TwoFaRepository::new(database.clone());
    seed_two_fa(database, 101, &RFC_SECRET.to_ascii_lowercase(), true, 0, None).await;

    // t=59 → counter 1。RFC 4226 counter 1 = 287082（当前步）。
    assert_eq!(repo.validate_login_code(101, "287082", 59).await, Ok(()));
    // counter 0 = 755224（前一步）与 counter 2 = 359152（后一步）均在 skew 内。
    assert_eq!(repo.validate_login_code(101, "755224", 59).await, Ok(()));
    assert_eq!(repo.validate_login_code(101, "359152", 59).await, Ok(()));
    // 输入先去空格。
    assert_eq!(repo.validate_login_code(101, "28 70 82", 59).await, Ok(()));
    assert_eq!(read_attempts(database, 101).await, (0, None, Some(59)));

    // counter 3 = 969429 在窗口外：失败并计数。
    assert_eq!(
        repo.validate_login_code(101, "969429", 59).await,
        Err(TwoFaError::Invalid)
    );
    assert_eq!(read_attempts(database, 101).await.0, 1);

    // 非法格式不增加失败次数。
    let before = read_attempts(database, 101).await.0;
    assert_eq!(
        repo.validate_login_code(101, "28708", 59).await,
        Err(TwoFaError::Invalid)
    );
    assert_eq!(
        repo.validate_login_code(101, "28708a", 59).await,
        Err(TwoFaError::Invalid)
    );
    assert_eq!(read_attempts(database, 101).await.0, before);
}

async fn backup_codes(database: &Database) {
    let repo = TwoFaRepository::new(database.clone());
    seed_two_fa(database, 201, RFC_SECRET, true, 0, None).await;

    // Go 格式规则：去 '-' 后转大写，必须 8 位 A-Z0-9。
    assert_eq!(
        repo.validate_backup_code(201, "ABCD-EFG", 1).await,
        Err(TwoFaError::Invalid)
    );
    assert_eq!(
        repo.validate_backup_code(201, "ABCD-EFG!", 1).await,
        Err(TwoFaError::Invalid)
    );
    assert_eq!(
        repo.validate_login_code(201, "ABCD-EFG", 1).await,
        Err(TwoFaError::Invalid)
    );
    assert_eq!(
        read_attempts(database, 201).await.0,
        0,
        "invalid format must not increment failed attempts"
    );

    // 格式正确但未命中：登录路径计数并使用“错误，请重试”文案。
    assert_eq!(
        repo.validate_backup_code(201, "ZZZZ-ZZZZ", 1).await,
        Ok(false)
    );
    assert_eq!(
        repo.validate_login_code(201, "ZZZZ-ZZZZ", 1).await,
        Err(TwoFaError::Incorrect)
    );
    assert_eq!(read_attempts(database, 201).await.0, 1);

    seed_backup_code(database, 201, "ABCD-EFGH", false).await;
    seed_backup_code(database, 201, "IJKL-MNOP", false).await;

    // 大小写、分隔符归一化 + 一次性。
    assert_eq!(
        repo.validate_backup_code(201, "abcd-efgh", 100).await,
        Ok(true)
    );
    assert_eq!(
        repo.validate_backup_code(201, "ABCD-EFGH", 101).await,
        Ok(false)
    );
    assert_eq!(
        repo.validate_backup_code(201, "ab-cd-ef-gh", 102).await,
        Ok(false)
    );
    assert_eq!(
        repo.validate_backup_code(201, "ijklmnop", 103).await,
        Ok(true)
    );
    assert_eq!(used_backup_code_count(database, 201).await, 2);
}

async fn concurrent_backup_winner(database: &Database) {
    let repo = TwoFaRepository::new(database.clone());
    seed_two_fa(database, 301, RFC_SECRET, true, 0, None).await;
    seed_backup_code(database, 301, "WXYZ-2345", false).await;

    let first = {
        let repo = repo.clone();
        tokio::spawn(async move { repo.validate_backup_code(301, "WXYZ-2345", 500).await })
    };
    let second = {
        let repo = repo.clone();
        tokio::spawn(async move { repo.validate_backup_code(301, "WXYZ-2345", 500).await })
    };
    let first = first.await.expect("join first backup validation");
    let second = second.await.expect("join second backup validation");
    assert!(
        matches!(
            (first, second),
            (Ok(true), Ok(false)) | (Ok(false), Ok(true))
        ),
        "exactly one concurrent validation must consume the code"
    );
    assert_eq!(used_backup_code_count(database, 301).await, 1);
}

async fn failure_counts_and_lockout(database: &Database) {
    let repo = TwoFaRepository::new(database.clone());
    seed_two_fa(database, 401, RFC_SECRET, true, 0, None).await;
    let now = 1_000;

    for attempt in 1..MAX_FAIL_ATTEMPTS {
        assert_eq!(
            repo.validate_login_code(401, "000000", now).await,
            Err(TwoFaError::Invalid)
        );
        assert_eq!(read_attempts(database, 401).await.0, attempt);
    }

    // 第 5 次失败触发 300 秒锁定；Go 的备用码分支随后复检锁定，因此文案是锁定。
    assert!(matches!(
        repo.validate_login_code(401, "000000", now).await,
        Err(TwoFaError::Locked { until }) if until == now + LOCKOUT_SECONDS
    ));
    let (failed_attempts, locked_until, _) = read_attempts(database, 401).await;
    assert_eq!(failed_attempts, MAX_FAIL_ATTEMPTS);
    assert_eq!(locked_until, Some(now + LOCKOUT_SECONDS));

    // 锁定期间正确 TOTP 也失败，且不增加失败次数。
    // t=1000 → counter 33 = 841346。
    assert!(matches!(
        repo.validate_login_code(401, "841346", now + 1).await,
        Err(TwoFaError::Locked { until }) if until == now + LOCKOUT_SECONDS
    ));
    assert_eq!(
        read_attempts(database, 401).await.0,
        MAX_FAIL_ATTEMPTS,
        "locked attempts must not increment"
    );
}

async fn lock_expiry(database: &Database) {
    let repo = TwoFaRepository::new(database.clone());
    seed_two_fa(
        database,
        402,
        RFC_SECRET,
        true,
        MAX_FAIL_ATTEMPTS,
        Some(1_300),
    )
    .await;

    // 锁定到期前，即使正确码也失败。
    // t=1299 → counter 43 = 303194。
    assert!(matches!(
        repo.validate_login_code(402, "303194", 1_299).await,
        Err(TwoFaError::Locked { until }) if until == 1_300
    ));
    assert_eq!(read_attempts(database, 402).await.0, MAX_FAIL_ATTEMPTS);

    // 到期后 failed_attempts 不归零：下一次失败立即再次锁定（6 次失败）。
    assert!(matches!(
        repo.validate_login_code(402, "000000", 1_300).await,
        Err(TwoFaError::Locked { until }) if until == 1_300 + LOCKOUT_SECONDS
    ));
    let (failed_attempts, locked_until, _) = read_attempts(database, 402).await;
    assert_eq!(failed_attempts, MAX_FAIL_ATTEMPTS + 1);
    assert_eq!(locked_until, Some(1_300 + LOCKOUT_SECONDS));
}

async fn success_resets_usage(database: &Database) {
    let repo = TwoFaRepository::new(database.clone());

    seed_two_fa(database, 501, RFC_SECRET, true, 3, None).await;
    assert_eq!(repo.validate_login_code(501, "287082", 59).await, Ok(()));
    assert_eq!(read_attempts(database, 501).await, (0, None, Some(59)));

    seed_two_fa(database, 502, RFC_SECRET, true, 4, None).await;
    seed_backup_code(database, 502, "QRST-UVWX", false).await;
    assert_eq!(
        repo.validate_login_code(502, "qrst-uvwx", 2_000).await,
        Ok(())
    );
    assert_eq!(read_attempts(database, 502).await, (0, None, Some(2_000)));
    assert_eq!(used_backup_code_count(database, 502).await, 1);
}

async fn scenarios(database: &Database) {
    totp_window(database).await;
    backup_codes(database).await;
    concurrent_backup_winner(database).await;
    failure_counts_and_lockout(database).await;
    lock_expiry(database).await;
    success_resets_usage(database).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_two_fa_login_contract() {
    let database = sqlite_database().await;
    scenarios(&database).await;
    database.close().await;

    let repo = TwoFaRepository::new(database.clone());
    assert_eq!(repo.by_user_id(101).await, Err(TwoFaError::Unavailable));
    assert_eq!(
        repo.validate_login_code(101, "287082", 59).await,
        Err(TwoFaError::Unavailable)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_two_fa_login_contract() {
    let dsn = std::env::var("TEST_POSTGRES_DSN")
        .expect("TEST_POSTGRES_DSN required; PostgreSQL must not be skipped");
    let options: PgConnectOptions = dsn
        .parse()
        .unwrap_or_else(|_| panic!("PostgreSQL fixture configuration is invalid"));
    let options = options.disable_statement_logging();
    let (admin, database, schema) = postgres_database(&options).await;

    scenarios(&database).await;
    database.close().await;

    let repo = TwoFaRepository::new(database.clone());
    assert_eq!(repo.by_user_id(101).await, Err(TwoFaError::Unavailable));

    drop_schema(&admin, &schema).await;
    admin.close().await;
}
