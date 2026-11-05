//! auth_flows 仓储契约测试；仅交远程 CI 执行真实 SQLite/PostgreSQL。
//!
//! Go 的时间列是 datetime，本测试夹具使用 DATETIME/TIMESTAMPTZ，
//! 仓储以 Unix 秒输入、按时间戳绑定并以 epoch 表达式读回。
use newapi_identity::auth_flow::{
    AuthFlowError, AuthFlowMatch, AuthFlowRepository, CreateAuthFlow, Purpose, auth_flow_key,
    token_hash,
};
use newapi_storage::Database;
use sqlx::{
    ConnectOptions, QueryBuilder,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::sync::atomic::{AtomicU64, Ordering};

const NOW: i64 = 1_700_000_000;
const RETENTION: i64 = 24 * 60 * 60;
const SECRET: &str = "test-session-secret";
static NEXT: AtomicU64 = AtomicU64::new(0);

fn repository(db: &Database) -> AuthFlowRepository {
    AuthFlowRepository::new(db.clone(), auth_flow_key(SECRET))
}

fn matching() -> AuthFlowMatch<'static> {
    AuthFlowMatch {
        purpose: Purpose::TwoFALogin,
        user_id: 0,
        session_id: "",
    }
}

fn draft(purpose: &str, expires_at: i64) -> CreateAuthFlow {
    CreateAuthFlow {
        purpose: purpose.into(),
        user_id: 7,
        session_id: "sid-1".into(),
        payload: r#"{"next":"/dashboard"}"#.into(),
        expires_at,
    }
}

async fn execute(db: &Database, sql: &'static str) {
    let result = match db {
        Database::Sqlite(pool) => sqlx::query(sql).execute(pool).await.map(|_| ()),
        Database::Postgres(pool) => sqlx::query(sql).execute(pool).await.map(|_| ()),
    };
    assert!(result.is_ok(), "fixture SQL failed");
}

async fn fixture(db: &Database) {
    match db {
        Database::Sqlite(_) => execute(
            db,
            "CREATE TABLE auth_flows (id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash CHAR(64) NOT NULL UNIQUE, purpose VARCHAR(32) NOT NULL, user_id BIGINT, session_id VARCHAR(64), payload TEXT, expires_at DATETIME NOT NULL, consumed_at DATETIME, created_at DATETIME)",
        )
        .await,
        Database::Postgres(_) => execute(
            db,
            "CREATE TABLE auth_flows (id BIGSERIAL PRIMARY KEY, token_hash CHAR(64) NOT NULL UNIQUE, purpose VARCHAR(32) NOT NULL, user_id BIGINT, session_id VARCHAR(64), payload TEXT, expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ, created_at TIMESTAMPTZ)",
        )
        .await,
    }
    execute(
        db,
        "CREATE INDEX idx_auth_flow_purpose_expiry ON auth_flows (purpose, expires_at)",
    )
    .await;
}

async fn stored_hashes(db: &Database) -> Vec<String> {
    let hashes: Vec<String> = match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar::<_, String>("SELECT token_hash FROM auth_flows ORDER BY id")
                .fetch_all(pool)
                .await
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar::<_, String>("SELECT token_hash FROM auth_flows ORDER BY id")
                .fetch_all(pool)
                .await
        }
    }
    .expect("read token hashes");
    // PG char(64) 可能带 bpchar 补位；本仓储读路径也只暴露 trim 后的摘要。
    hashes
        .into_iter()
        .map(|hash| hash.trim().to_owned())
        .collect()
}

async fn consumed_at(db: &Database, token_hash: &str) -> Option<i64> {
    match db {
        Database::Sqlite(pool) => sqlx::query_scalar::<_, Option<i64>>(
            "SELECT CAST(strftime('%s',consumed_at) AS INTEGER) FROM auth_flows WHERE token_hash=$1",
        )
        .bind(token_hash)
        .fetch_one(pool)
        .await,
        Database::Postgres(pool) => sqlx::query_scalar::<_, Option<i64>>(
            "SELECT CAST(EXTRACT(EPOCH FROM consumed_at) AS BIGINT) FROM auth_flows WHERE token_hash=$1",
        )
        .bind(token_hash)
        .fetch_one(pool)
        .await,
    }
    .expect("read consumed_at")
}

async fn scenarios(db: &Database, other: &Database) {
    let repo = repository(db);
    let other_repo = repository(other);
    let key = auth_flow_key(SECRET);

    // 输入校验：purpose 仅空白、expires_at 不晚于 now。
    assert_eq!(
        repo.create(
            CreateAuthFlow {
                purpose: "   ".into(),
                ..draft(Purpose::TwoFALogin, NOW + 60)
            },
            NOW
        )
        .await
        .err(),
        Some(AuthFlowError::Invalid)
    );
    assert_eq!(
        repo.create(draft(Purpose::TwoFALogin, NOW), NOW)
            .await
            .err(),
        Some(AuthFlowError::Invalid)
    );

    // 创建：数据库只保存 HMAC，不保存原始 token。
    let (token, flow) = repo
        .create(draft(Purpose::TwoFALogin, NOW + 60), NOW)
        .await
        .expect("create");
    let raw = token.expose_secret();
    assert_eq!(raw.len(), 43);
    assert!(!raw.contains('='));
    assert_eq!(flow.token_hash, token_hash(&key, raw));
    assert_ne!(flow.token_hash, raw);
    assert_eq!(flow.purpose, Purpose::TwoFALogin);
    assert_eq!(flow.user_id, 7);
    assert_eq!(flow.session_id, "sid-1");
    assert_eq!(flow.payload, r#"{"next":"/dashboard"}"#);
    assert_eq!(flow.expires_at, NOW + 60);
    assert_eq!(flow.created_at, NOW);
    assert_eq!(flow.consumed_at, None);
    assert_eq!(stored_hashes(db).await, vec![flow.token_hash.clone()]);

    // Get 只读且不消费。
    let got = repo.get(raw, matching(), NOW).await.expect("get");
    assert_eq!(got.id, flow.id);
    assert_eq!(got.token_hash, flow.token_hash);
    assert_eq!(got.consumed_at, None);
    assert_eq!(consumed_at(db, &flow.token_hash).await, None);

    // purpose/user/session 绑定任一不匹配都是 Invalid，且不消耗原 flow。
    for bad in [
        AuthFlowMatch {
            purpose: "oauth",
            ..matching()
        },
        AuthFlowMatch {
            user_id: 99,
            ..matching()
        },
        AuthFlowMatch {
            session_id: "other-sid",
            ..matching()
        },
    ] {
        assert_eq!(
            repo.get(raw, bad, NOW).await.err(),
            Some(AuthFlowError::Invalid)
        );
    }
    assert_eq!(
        repo.get(raw, matching(), NOW).await.expect("still get").id,
        flow.id
    );

    // 原子消费一次；再次 Get/Consume 都是 Consumed。
    let consumed = repo.consume(raw, matching(), NOW).await.expect("consume");
    assert_eq!(consumed.consumed_at, Some(NOW));
    assert_eq!(consumed_at(db, &flow.token_hash).await, Some(NOW));
    assert_eq!(
        repo.get(raw, matching(), NOW).await.err(),
        Some(AuthFlowError::Consumed)
    );
    assert_eq!(
        repo.consume(raw, matching(), NOW).await.err(),
        Some(AuthFlowError::Consumed)
    );

    // 过期：expires_at == now 即过期，且 Get 不消费。
    let (expired_token, expired) = repo
        .create(draft(Purpose::TwoFALogin, NOW + 10), NOW)
        .await
        .expect("create expiring");
    assert_eq!(
        repo.get(expired_token.expose_secret(), matching(), NOW + 10)
            .await
            .err(),
        Some(AuthFlowError::Expired)
    );
    assert_eq!(
        repo.consume(expired_token.expose_secret(), matching(), NOW + 10)
            .await
            .err(),
        Some(AuthFlowError::Expired)
    );
    assert_eq!(consumed_at(db, &expired.token_hash).await, None);

    // Go 顺序：已消费优先于过期；已消费且此刻过期仍返回 Consumed。
    let (ordering_token, ordering) = repo
        .create(draft(Purpose::TwoFALogin, NOW + 10), NOW)
        .await
        .expect("create ordering");
    repo.consume(ordering_token.expose_secret(), matching(), NOW)
        .await
        .expect("consume before expiry");
    assert_eq!(
        repo.get(ordering_token.expose_secret(), matching(), NOW + 10)
            .await
            .err(),
        Some(AuthFlowError::Consumed)
    );
    assert_eq!(
        repo.consume(ordering_token.expose_secret(), matching(), NOW + 10)
            .await
            .err(),
        Some(AuthFlowError::Consumed)
    );
    assert_eq!(consumed_at(db, &ordering.token_hash).await, Some(NOW));

    // 真实并发：同一 token 只能有一个赢家。
    let (race_token, race) = repo
        .create(draft(Purpose::TwoFALogin, NOW + 60), NOW)
        .await
        .expect("create race");
    let race_raw = race_token.expose_secret().to_owned();
    let (one, two) = tokio::join!(
        repo.consume(&race_raw, matching(), NOW),
        other_repo.consume(&race_raw, matching(), NOW)
    );
    assert_eq!(
        [one.is_ok(), two.is_ok()]
            .into_iter()
            .filter(|ok| *ok)
            .count(),
        1,
        "exactly one concurrent consumer may win"
    );
    for result in [&one, &two] {
        if let Err(error) = result {
            // SQLite 并发写可能报锁冲突；PG 输家为 Consumed。
            assert!(matches!(
                *error,
                AuthFlowError::Consumed | AuthFlowError::Storage
            ));
        }
    }
    assert_eq!(consumed_at(db, &race.token_hash).await, Some(NOW));
    assert_eq!(
        repo.consume(&race_raw, matching(), NOW).await.err(),
        Some(AuthFlowError::Consumed)
    );

    // 清理边界：严格小于 cutoff；已消费时间同样严格小于。
    let cleanup_now = NOW + 1_000_000;
    let cutoff = cleanup_now - RETENTION;
    let (_, expired_before) = repo
        .create(draft(Purpose::TwoFALogin, cutoff - 1), 0)
        .await
        .expect("cleanup expired");
    let (_, expired_at) = repo
        .create(draft(Purpose::TwoFALogin, cutoff), 0)
        .await
        .expect("cleanup expiry boundary");
    let (consumed_before_token, consumed_before) = repo
        .create(draft(Purpose::TwoFALogin, cleanup_now + 1000), 0)
        .await
        .expect("cleanup consumed");
    repo.consume(
        consumed_before_token.expose_secret(),
        matching(),
        cutoff - 1,
    )
    .await
    .expect("consume before cutoff");
    let (consumed_at_token, consumed_at_boundary) = repo
        .create(draft(Purpose::TwoFALogin, cleanup_now + 1000), 0)
        .await
        .expect("cleanup consumed boundary");
    repo.consume(consumed_at_token.expose_secret(), matching(), cutoff)
        .await
        .expect("consume at cutoff");
    let (_, unconsumed) = repo
        .create(draft(Purpose::TwoFALogin, cleanup_now + 1000), 0)
        .await
        .expect("cleanup unconsumed");

    let before = stored_hashes(db).await;
    let deleted = repo.delete_expired(cleanup_now).await.expect("cleanup");
    let after = stored_hashes(db).await;
    assert_eq!(before.len() as u64 - after.len() as u64, deleted);
    assert!(!after.contains(&expired_before.token_hash));
    assert!(after.contains(&expired_at.token_hash));
    assert!(!after.contains(&consumed_before.token_hash));
    assert!(after.contains(&consumed_at_boundary.token_hash));
    assert!(after.contains(&unconsumed.token_hash));
}

fn sqlite_dsn() -> String {
    format!(
        "sqlite:file:auth_flow_fixture_{}_{}?mode=memory&cache=shared",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

#[tokio::test]
async fn sqlite_in_memory_auth_flow_contract() {
    // 真实内存库：同名 file: 共享缓存使两个连接看到同一数据库。
    let db = Database::connect(&sqlite_dsn())
        .await
        .expect("SQLite in-memory fixture");
    fixture(&db).await;
    scenarios(&db, &db).await;
    db.close().await;
}

#[tokio::test]
async fn sqlite_closed_pool_returns_storage() {
    let db = Database::connect(&sqlite_dsn())
        .await
        .expect("SQLite in-memory fixture");
    fixture(&db).await;
    let repo = repository(&db);
    let (token, _) = repo
        .create(draft(Purpose::TwoFALogin, NOW + 60), NOW)
        .await
        .expect("create before close");
    db.close().await;
    assert_eq!(
        repo.get(token.expose_secret(), matching(), NOW).await.err(),
        Some(AuthFlowError::Storage)
    );
    assert_eq!(
        repo.create(draft(Purpose::TwoFALogin, NOW + 60), NOW)
            .await
            .err(),
        Some(AuthFlowError::Storage)
    );
}

#[tokio::test]
async fn postgres_auth_flow_contract() {
    let dsn = std::env::var("TEST_POSTGRES_DSN")
        .expect("TEST_POSTGRES_DSN required; PostgreSQL must not be skipped");
    let options: PgConnectOptions = dsn
        .parse()
        .unwrap_or_else(|_| panic!("invalid PostgreSQL fixture config"));
    let options = options.disable_statement_logging();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap_or_else(|_| panic!("PostgreSQL fixture connection failed"));
    let schema = format!(
        "auth_flow_fixture_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    assert!(
        schema.starts_with("auth_flow_fixture_")
            && schema
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "isolated schema name must be a fixed identifier"
    );
    let mut create = QueryBuilder::new("CREATE SCHEMA \"");
    create.push(&schema).push("\"");
    create
        .build()
        .execute(&admin)
        .await
        .expect("isolated schema");
    let mut pools = Vec::new();
    for _ in 0..2 {
        let search_path = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .after_connect(move |conn, _| {
                let path = search_path.clone();
                Box::pin(async move {
                    // 值可绑定，避免拼接 SET search_path。
                    sqlx::query("SELECT set_config('search_path',$1,false)")
                        .bind(path)
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options.clone())
            .await
            .unwrap_or_else(|_| panic!("isolated PostgreSQL pool failed"));
        pools.push(Database::Postgres(pool));
    }
    fixture(&pools[0]).await;
    scenarios(&pools[0], &pools[1]).await;

    // 连接关闭后所有查询失败关闭为 Storage。
    let repo = repository(&pools[0]);
    let (token, _) = repo
        .create(draft(Purpose::TwoFALogin, NOW + 60), NOW)
        .await
        .expect("create before close");
    for pool in &pools {
        pool.close().await;
    }
    assert_eq!(
        repo.get(token.expose_secret(), matching(), NOW).await.err(),
        Some(AuthFlowError::Storage)
    );

    let mut drop_schema = QueryBuilder::new("DROP SCHEMA \"");
    drop_schema.push(&schema).push("\" CASCADE");
    drop_schema
        .build()
        .execute(&admin)
        .await
        .expect("cleanup isolated schema");
    admin.close().await;
}
