//! 仅交远程 CI 执行；合成隔离 DDL 不是生产迁移。
use std::sync::{Mutex, atomic::{AtomicU64, Ordering}};
use newapi_identity::sessions::{CreateSession, NoCache, RefreshHash, RefreshOutcome,
    RevocationFence, SessionError, SessionLimits, SessionMetadata, SessionRepository};
use newapi_storage::Database;
use sqlx::{ConnectOptions, postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions}};

// 两个分支分别推导 QueryBuilder 的数据库类型，不使用 Any 或 SQL 安全断言。
macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

const NOW: i64 = 1_700_000_000;
static NEXT: AtomicU64 = AtomicU64::new(0);
fn hash(c: char) -> RefreshHash {
    RefreshHash::from_lower_hex(c.to_string().repeat(64)).ok().expect("synthetic digest")
}
fn draft(sid: &str) -> CreateSession {
    CreateSession { sid: sid.into(), user_id: 1, expected_auth_version: Some(3),
        refresh_hash: hash('a'), login_method: " password ".into(),
        ip: " 127.0.0.1 ".into(), user_agent: " x ".into() }
}
// 仅接受源码常量；动态业务值另用 push_bind，不提供任意 String SQL 入口。
async fn execute(db: &Database, sql: &'static str) {
    let result = match db {
        Database::Sqlite(p) => sqlx::QueryBuilder::new(sql).build().execute(p).await.map(|_| ()),
        Database::Postgres(p) => sqlx::QueryBuilder::new(sql).build().execute(p).await.map(|_| ()),
    };
    assert!(result.is_ok(), "fixture SQL failed (details redacted)");
}
async fn fixture(db: &Database) {
    execute(db, "CREATE TABLE users (id INTEGER PRIMARY KEY,status INTEGER,auth_version BIGINT NOT NULL DEFAULT 1,deleted_at TIMESTAMP)").await;
    execute(db, "INSERT INTO users VALUES (1,1,3,NULL),(2,1,1,NULL)").await;
    execute(db, "CREATE TABLE user_sessions (
        sid VARCHAR(64) PRIMARY KEY,user_id INTEGER NOT NULL,version BIGINT NOT NULL DEFAULT 1,
        user_auth_version BIGINT NOT NULL,status VARCHAR(16) NOT NULL,refresh_hash CHAR(64) NOT NULL,
        previous_refresh_hash VARCHAR(64),previous_valid_until BIGINT NOT NULL DEFAULT 0,
        login_method VARCHAR(32) NOT NULL,ip VARCHAR(64),user_agent TEXT,created_at BIGINT,
        last_active_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,revoked_at BIGINT NOT NULL DEFAULT 0,
        revoked_reason VARCHAR(64))").await;
    // 标识符不能绑定，直接固定整个索引 DDL 白名单。
    for ddl in [
        "CREATE INDEX idx_user_sessions_user_status_expiry ON user_sessions (user_id,status,expires_at)",
        "CREATE INDEX idx_user_sessions_user_created ON user_sessions (user_id,created_at)",
        "CREATE INDEX idx_user_sessions_status_revoked ON user_sessions (status,revoked_at)",
        "CREATE INDEX idx_user_sessions_expires_at ON user_sessions (expires_at)",
    ] { execute(db, ddl).await; }
}

struct SpyFence {
    events: Mutex<Vec<String>>,
    fail_pending: bool,
    fail_terminal: bool,
    fail_sid: Option<String>,
}
impl SpyFence {
    fn new() -> Self {
        Self { events: Mutex::new(Vec::new()), fail_pending: false, fail_terminal: false, fail_sid: None }
    }
}
impl RevocationFence for SpyFence {
    async fn revoking(&self, m: &SessionMetadata, _: i64, _: &str) -> Result<(), SessionError> {
        self.events.lock().expect("spy mutex").push(format!("pending:{}", m.sid));
        if self.fail_pending || self.fail_sid.as_deref() == Some(m.sid.as_str()) {
            Err(SessionError::Fence)
        } else { Ok(()) }
    }
    async fn revoked(&self, m: &SessionMetadata, _: i64) -> Result<(), SessionError> {
        assert_eq!(m.status, "revoked");
        self.events.lock().expect("spy mutex").push(format!("terminal:{}", m.sid));
        if self.fail_terminal { Err(SessionError::Fence) } else { Ok(()) }
    }
}

async fn scenarios(db: &Database, _second: &Database) {
    fixture(db).await;
    let repo = SessionRepository::new(db.clone());
    let no_cache = NoCache::explicitly_disabled();
    assert!(RefreshHash::from_lower_hex("A".repeat(64)).is_err());
    assert!(RefreshHash::from_lower_hex("raw-refresh-secret".into()).is_err());
    let mut split_utf8 = draft("split-utf8");
    split_utf8.ip = "界".repeat(22);
    assert!(matches!(repo.create(split_utf8, SessionLimits::default(), NOW).await, Err(SessionError::MetadataEncodingUnsupported)));
    assert!(repo.authoritative("split-utf8").await.expect("读取").is_none());
    let mut split_ua = draft("split-ua");
    split_ua.user_agent = "界".repeat(171);
    assert!(matches!(repo.create(split_ua, SessionLimits::default(), NOW).await, Err(SessionError::MetadataEncodingUnsupported)));
    assert!(repo.authoritative("split-ua").await.expect("读取").is_none());
    // 64/512 字节恰好在字符边界时必须原样保留；超限 ASCII 也按字节截断。
    let mut boundary = draft("boundary");
    boundary.ip = format!(" {}aZ ", "界".repeat(21));
    boundary.user_agent = format!(" {}abZ ", "界".repeat(170));
    let row = repo.create(boundary, SessionLimits::default(), NOW).await.expect("完整字符边界");
    assert_eq!(row.metadata.ip, format!("{}a", "界".repeat(21)));
    assert_eq!(row.metadata.user_agent, format!("{}ab", "界".repeat(170)));
    assert_eq!(row.metadata.ip.len(), 64);
    assert_eq!(row.metadata.user_agent.len(), 512);
    let s = repo.create(draft("main"), SessionLimits::default(), NOW).await.expect("create");
    assert_eq!(s.metadata.version, 1);
    assert_eq!(s.metadata.user_auth_version, 3);
    assert_eq!(s.metadata.expires_at, NOW + 30 * 86400);
    assert_eq!(s.metadata.login_method, "password");
    assert_eq!(s.metadata.ip, "127.0.0.1");
    assert_eq!(s.metadata.user_agent, "x");
    assert!(repo.validate_access(1, "main", 1, 3, NOW).await.is_ok());
    for (id, sv, uv) in [(2,1,3),(1,2,3),(1,1,4)] {
        assert!(matches!(repo.validate_access(id, "main", sv, uv, NOW).await, Err(SessionError::Inactive)));
    }
    assert!(matches!(repo.validate_access(1,"main",1,3,NOW+30*86400).await, Err(SessionError::Inactive)));
    let rotated = repo.rotate(&no_cache,1,"main",&hash('a'),&hash('b'),NOW+10).await.expect("rotate");
    let RefreshOutcome::Rotated(rotated) = rotated else { panic!("expected rotation") };
    assert!(rotated.current_hash_matches(&hash('b')));
    assert_eq!(rotated.metadata.version, 1);
    assert_eq!(rotated.metadata.expires_at, s.metadata.expires_at);
    for time in [NOW+20, NOW+40] {
        let outcome = repo.rotate(&no_cache,1,"main",&hash('a'),&hash('b'),time).await.expect("previous grace");
        let RefreshOutcome::PreviousWithinGrace(row) = outcome else { panic!("expected distinct grace outcome") };
        assert!(row.current_hash_matches(&hash('b')));
    }
    let spy = SpyFence::new();
    assert!(matches!(repo.rotate(&spy,1,"main",&hash('c'),&hash('d'),NOW+41).await, Err(SessionError::Invalid)));
    assert!(spy.events.lock().expect("spy mutex").is_empty());
    assert!(repo.validate_access(1,"main",1,3,NOW+41).await.is_ok());
    let reuse = repo.rotate(&spy,1,"main",&hash('a'),&hash('b'),NOW+41).await.expect("reuse revoke");
    let RefreshOutcome::Reused(report) = reuse else { panic!("expected reuse") };
    assert_eq!(report.revoked_count, 1);
    assert_eq!(*spy.events.lock().expect("spy mutex"), vec!["pending:main", "terminal:main"]);
    assert_eq!(repo.authoritative("main").await.expect("read").expect("row").metadata.revoked_reason, "refresh_reuse");

    // 兼容 NULL/旧 CHAR 空格填充；仅保存紧邻的上一代 hash。
    repo.create(draft("legacy"), SessionLimits::default(), NOW).await.expect("create");
    execute(db, "UPDATE user_sessions SET previous_refresh_hash=NULL,ip=NULL,user_agent=NULL,revoked_reason=NULL WHERE sid='legacy'").await;
    assert!(repo.authoritative("legacy").await.expect("nullable read").is_some());
    // 仅在隔离 fixture 中复现旧 CHAR(64) 存储。
    if matches!(db, Database::Postgres(_)) {
        execute(db, "ALTER TABLE user_sessions ALTER COLUMN previous_refresh_hash TYPE CHAR(64)").await;
    }
    backend!(db, pool, {
        let mut query = sqlx::QueryBuilder::new("UPDATE user_sessions SET previous_refresh_hash=");
        query.push_bind("b".repeat(64)).push(",previous_valid_until=").push_bind(NOW+30)
            .push(" WHERE sid=").push_bind("legacy");
        assert!(query.build().execute(pool).await.is_ok(), "设置 previous fixture 失败");
    });
    assert!(matches!(repo.rotate(&no_cache,1,"legacy",&hash('b'),&hash('c'),NOW+20).await,
        Ok(RefreshOutcome::PreviousWithinGrace(_))));
}

async fn remaining_scenarios(db: &Database, second: &Database) {
    let repo = SessionRepository::new(db.clone());
    let other = SessionRepository::new(second.clone());
    let no_cache = NoCache::explicitly_disabled();
    execute(db, "UPDATE user_sessions SET previous_refresh_hash='   ' WHERE sid='legacy'").await;
    assert!(matches!(repo.rotate(&no_cache,1,"legacy",&hash('f'),&hash('e'),NOW+1).await, Err(SessionError::Invalid)));
    repo.rotate(&no_cache,1,"legacy",&hash('a'),&hash('b'),NOW+2).await.expect("first generation");
    repo.rotate(&no_cache,1,"legacy",&hash('b'),&hash('c'),NOW+3).await.expect("second generation");
    let old_spy = SpyFence::new();
    assert!(matches!(repo.rotate(&old_spy,1,"legacy",&hash('a'),&hash('b'),NOW+90).await, Err(SessionError::Invalid)));
    assert!(old_spy.events.lock().expect("spy mutex").is_empty());
    assert!(repo.validate_access(1,"legacy",1,3,NOW+90).await.is_ok());
    repo.create(draft("parallel"), SessionLimits::default(), NOW).await.expect("create");
    let a = hash('a'); let b = hash('b');
    let (one, two) = tokio::join!(
        repo.rotate(&no_cache,1,"parallel",&a,&b,NOW+10),
        other.rotate(&no_cache,1,"parallel",&a,&b,NOW+10));
    let one = one.expect("first refresh"); let two = two.expect("second refresh");
    assert!(matches!((&one,&two), (RefreshOutcome::Rotated(_),RefreshOutcome::PreviousWithinGrace(_)) |
        (RefreshOutcome::PreviousWithinGrace(_),RefreshOutcome::Rotated(_))));
    let row = repo.authoritative("parallel").await.expect("read").expect("row");
    assert_eq!(row.metadata.version, 1);
    assert!(row.current_hash_matches(&b));
    // 仅凭 cookie 撤销时，未知 secret 不能发布 fence。
    let spy = SpyFence::new();
    assert_eq!(repo.revoke_by_refresh(&spy,"parallel",&hash('f'),"logout",NOW+20).await.expect("logout").revoked_count, 0);
    assert!(spy.events.lock().expect("spy mutex").is_empty());
    assert_eq!(repo.revoke_by_refresh(&spy,"parallel",&a,"logout",NOW+40).await.expect("previous logout").revoked_count, 1);

    repo.create(draft("fenced"), SessionLimits::default(), NOW).await.expect("create");
    let mut failing = SpyFence::new(); failing.fail_pending = true;
    assert_eq!(repo.revoke(&failing,1,"fenced","logout",NOW+1).await, Err(SessionError::Fence));
    assert!(repo.validate_access(1,"fenced",1,3,NOW+1).await.is_ok());
    assert_eq!(repo.revoke(&spy,2,"fenced","logout",NOW+1).await.expect("cross-user").revoked_count, 0);
    failing.fail_pending = false; failing.fail_terminal = true;
    let report = repo.revoke(&failing,1,"fenced","logout",NOW+2).await.expect("committed despite cache failure");
    assert_eq!(report.revoked_count, 1);
    assert_eq!(report.terminal_fence_failures, 1);
    assert_eq!(repo.revoke(&spy,1,"fenced","logout",NOW+3).await.expect("idempotence").revoked_count, 0);

    // pending fence 成功后 SQL 实际失败，不能发布终态或撤销 pending。
    repo.create(draft("rollback"), SessionLimits::default(), NOW).await.expect("create");
    match db {
        Database::Sqlite(_) => execute(db, "CREATE TRIGGER reject_revoke BEFORE UPDATE ON user_sessions WHEN NEW.sid='rollback' AND NEW.status='revoked' BEGIN SELECT RAISE(ABORT,'fixture'); END").await,
        Database::Postgres(_) => execute(db, "ALTER TABLE user_sessions ADD CONSTRAINT reject_revoke CHECK (sid <> 'rollback' OR status <> 'revoked')").await,
    }
    let rollback_spy = SpyFence::new();
    assert_eq!(repo.revoke(&rollback_spy,1,"rollback","logout",NOW+1).await, Err(SessionError::Storage));
    assert_eq!(*rollback_spy.events.lock().expect("spy mutex"), vec!["pending:rollback"]);
    assert!(repo.validate_access(1,"rollback",1,3,NOW+1).await.is_ok());
    match db {
        Database::Sqlite(_) => execute(db, "DROP TRIGGER reject_revoke").await,
        Database::Postgres(_) => execute(db, "ALTER TABLE user_sessions DROP CONSTRAINT reject_revoke").await,
    }

    execute(db, "UPDATE users SET status=2 WHERE id=1").await;
    assert!(matches!(repo.validate_access(1,"rollback",1,3,NOW).await, Err(SessionError::UserSecurityChanged)));
    assert!(matches!(repo.create(draft("disabled"),SessionLimits::default(),NOW).await, Err(SessionError::UserSecurityChanged)));
    let security_spy = SpyFence::new();
    assert!(matches!(repo.rotate(&security_spy,1,"rollback",&hash('f'),&hash('e'),NOW+2).await,
        Err(SessionError::Invalid)));
    assert!(security_spy.events.lock().expect("spy mutex").is_empty());
    repo.create(draft("unused-disabled"),SessionLimits::default(),NOW).await.err().expect("disabled rejects create");
    execute(db, "UPDATE users SET status=1,auth_version=4 WHERE id=1").await;
    assert!(matches!(repo.validate_access(1,"rollback",1,3,NOW).await, Err(SessionError::UserSecurityChanged)));
    assert!(repo.list(1,"rollback",NOW).await.expect("list stale versions").is_empty());
    execute(db, "UPDATE users SET auth_version=3,deleted_at='2026-01-01 00:00:00' WHERE id=1").await;
    assert!(matches!(repo.validate_access(1,"rollback",1,3,NOW).await, Err(SessionError::UserSecurityChanged)));
    execute(db, "UPDATE users SET deleted_at=NULL WHERE id=1").await;
    let limits = SessionLimits { active: 1, ..SessionLimits::default() };
    assert!(matches!(repo.create(draft("limit"),limits,NOW).await, Err(SessionError::ActiveLimit)));
    execute(db, "UPDATE user_sessions SET status='revoked'").await;
    let limits = SessionLimits { issued: 1, ..SessionLimits::default() };
    assert!(matches!(repo.create(draft("issued"),limits,NOW).await, Err(SessionError::IssuanceLimit)));

    execute(db, "DELETE FROM user_sessions").await;
    // 用合成批量数据测试，不为生产仓储增加绕过会话上限的入口。
    let seed = draft("keep");
    repo.create(seed,SessionLimits::default(),NOW).await.expect("create current");
    for i in 0_i64..501 {
        backend!(db, pool, {
            let mut query = sqlx::QueryBuilder::new("INSERT INTO user_sessions (sid,user_id,version,user_auth_version,status,refresh_hash,previous_refresh_hash,previous_valid_until,login_method,ip,user_agent,created_at,last_active_at,expires_at,revoked_at,revoked_reason) SELECT ");
            query.push_bind(format!("other-{i:04}"))
                .push(",user_id,version,user_auth_version,status,refresh_hash,previous_refresh_hash,previous_valid_until,login_method,ip,user_agent,created_at,last_active_at+")
                .push_bind(i).push(",expires_at,revoked_at,revoked_reason FROM user_sessions WHERE sid=")
                .push_bind("keep");
            assert!(query.build().execute(pool).await.is_ok(), "批量 fixture 写入失败");
        });
    }
    let listed = repo.list(1,"keep",NOW).await.expect("list");
    assert_eq!(listed.len(), 100);
    assert_eq!(listed[0].sid,"keep");
    assert_eq!(listed[1].sid,"other-0500");
    let mut batch_spy = SpyFence::new(); batch_spy.fail_sid = Some("other-0500".into());
    let failure = repo.revoke_others(&batch_spy,1,"keep","other_logout",NOW+1).await.expect_err("second batch fence failure");
    assert_eq!(failure.error, SessionError::Fence);
    assert_eq!(failure.committed.revoked_count, 500);
    assert!(repo.validate_access(1,"keep",1,3,NOW+1).await.is_ok());
    assert!(repo.validate_access(1,"other-0500",1,3,NOW+1).await.is_ok());
    assert_eq!(repo.revoke_others(&no_cache,1,"keep","other_logout",NOW+1).await.expect("retry").revoked_count, 1);
}

// 验证数据库字节边界，不冒充已执行 Go 驱动差分：
// SQLite 用 BLOB -> TEXT 保持原字节，再转 BLOB 读取，避免 Rust String 解码；
// PG convert_from 明确要求 UTF8，必须返回 22021，不能只断言任意错误。
async fn metadata_encoding_boundary(db: &Database) {
    execute(db, "CREATE TABLE metadata_encoding_fixture (value TEXT)").await;
    for (input, limit) in [("界".repeat(22), 64), ("界".repeat(171), 512)] {
        let bytes = input.as_bytes()[..limit].to_vec();
        assert_eq!(bytes.len(), limit);
        assert!(std::str::from_utf8(&bytes).is_err());
        match db {
            Database::Sqlite(pool) => {
                let mut insert = sqlx::QueryBuilder::new("INSERT INTO metadata_encoding_fixture(value) VALUES (CAST(");
                insert.push_bind(bytes.clone()).push(" AS TEXT))");
                insert.build().execute(pool).await.expect("SQLite 保存非法 UTF8 字节");
                let stored: Vec<u8> = sqlx::query_scalar("SELECT CAST(value AS BLOB) FROM metadata_encoding_fixture").fetch_one(pool).await.expect("按字节回读");
                assert_eq!(stored, bytes);
                let kind: String = sqlx::query_scalar("SELECT typeof(value) FROM metadata_encoding_fixture").fetch_one(pool).await.expect("TEXT 存储类型");
                assert_eq!(kind, "text");
            }
            Database::Postgres(pool) => {
                let encoding: String = sqlx::query_scalar("SHOW server_encoding").fetch_one(pool).await.expect("服务端编码");
                assert_eq!(encoding, "UTF8", "本边界 fixture 要求 UTF8 PostgreSQL");
                let mut insert = sqlx::QueryBuilder::new("INSERT INTO metadata_encoding_fixture(value) VALUES (convert_from(");
                insert.push_bind(bytes).push(",'UTF8'))");
                let error = insert.build().execute(pool).await.expect_err("PG 必须拒绝非法 UTF8");
                assert_eq!(error.as_database_error().and_then(|e| e.code()).as_deref(), Some("22021"));
            }
        }
        execute(db, "DELETE FROM metadata_encoding_fixture").await;
    }
    execute(db, "DROP TABLE metadata_encoding_fixture").await;
}

#[tokio::test]
async fn sqlite_session_repository_contract() {
    let path = std::env::temp_dir().join(format!("session_fixture_{}_{}.sqlite",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));
    let options = SqliteConnectOptions::new().filename(&path).create_if_missing(true)
        .busy_timeout(std::time::Duration::from_secs(10)).disable_statement_logging();
    let first = SqlitePoolOptions::new().max_connections(3).connect_with(options.clone()).await.expect("SQLite fixture");
    let second = SqlitePoolOptions::new().max_connections(3).connect_with(options).await.expect("SQLite second pool");
    let db = Database::Sqlite(first); let other = Database::Sqlite(second);
    metadata_encoding_boundary(&db).await;
    scenarios(&db,&other).await;
    remaining_scenarios(&db,&other).await;
    db.close().await; other.close().await;
    std::fs::remove_file(path).expect("remove isolated SQLite fixture");
}

#[tokio::test]
async fn postgres_session_repository_contract() {
    let dsn = std::env::var("TEST_POSTGRES_DSN").expect("TEST_POSTGRES_DSN required; PostgreSQL must not be skipped");
    let options: PgConnectOptions = dsn.parse().unwrap_or_else(|_| panic!("invalid PostgreSQL fixture config"));
    let options = options.disable_statement_logging();
    let admin = PgPoolOptions::new().max_connections(1).connect_with(options.clone()).await
        .unwrap_or_else(|_| panic!("PostgreSQL fixture connection failed"));
    let schema = format!("session_fixture_{}_{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed));
    // DDL 标识符无法参数绑定：仅允许固定前缀和本进程生成的数字/下划线。
    assert!(schema.starts_with("session_fixture_") && schema.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'));
    let mut create = sqlx::QueryBuilder::new("CREATE SCHEMA \"");
    create.push(&schema).push("\"");
    create.build().execute(&admin).await.expect("isolated schema");
    let mut pools = Vec::new();
    for _ in 0..2 {
        let path = schema.clone();
        let pool = PgPoolOptions::new().max_connections(3).after_connect(move |conn,_| {
            let path = path.clone();
            Box::pin(async move {
                // set_config 的值可绑定，避免拼接 SET search_path。
                let mut query = sqlx::QueryBuilder::new("SELECT set_config('search_path',");
                query.push_bind(path).push(",false)");
                query.build().execute(conn).await?;
                Ok(())
            })
        }).connect_with(options.clone()).await.unwrap_or_else(|_| panic!("isolated PostgreSQL pool failed"));
        pools.push(Database::Postgres(pool));
    }
    metadata_encoding_boundary(&pools[0]).await;
    scenarios(&pools[0],&pools[1]).await;
    remaining_scenarios(&pools[0],&pools[1]).await;
    for p in &pools { p.close().await; }
    let mut drop_schema = sqlx::QueryBuilder::new("DROP SCHEMA \"");
    drop_schema.push(&schema).push("\" CASCADE");
    drop_schema.build().execute(&admin).await.expect("cleanup isolated schema");
    admin.close().await;
}
