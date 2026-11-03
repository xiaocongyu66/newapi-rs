//! 认证编排的真实数据库测试；只使用隔离 SQLite 文件，不起服务。
use std::sync::atomic::{AtomicU64, Ordering};

use newapi_identity::{
    auth_session::{SessionAuth, SessionAuthError},
    crypto::{AuthKeys, RefreshCredential},
    sessions::{CreateSession, RefreshHash, SessionLimits, SessionRepository},
};
use newapi_storage::Database;
use sqlx::{
    ConnectOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const NOW: i64 = 1_700_000_000;

async fn fixture() -> (Database, SessionAuth<newapi_identity::sessions::NoCache>) {
    let path = std::env::temp_dir().join(format!(
        "auth_session_fixture_{}_{}.sqlite",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .busy_timeout(std::time::Duration::from_secs(30))
        .disable_statement_logging();
    let pool = SqlitePoolOptions::new()
        .max_connections(3)
        .connect_with(options)
        .await
        .expect("SQLite fixture");
    for ddl in [
        "CREATE TABLE users (id INTEGER PRIMARY KEY,status INTEGER,auth_version BIGINT NOT NULL DEFAULT 1,deleted_at TIMESTAMP)",
        "INSERT INTO users VALUES (1,1,3,NULL)",
        "CREATE TABLE user_sessions (sid VARCHAR(64) PRIMARY KEY,user_id INTEGER NOT NULL,version BIGINT NOT NULL DEFAULT 1,user_auth_version BIGINT NOT NULL,status VARCHAR(16) NOT NULL,refresh_hash CHAR(64) NOT NULL,previous_refresh_hash VARCHAR(64),previous_valid_until BIGINT NOT NULL DEFAULT 0,login_method VARCHAR(32) NOT NULL,ip VARCHAR(64),user_agent TEXT,created_at BIGINT,last_active_at BIGINT NOT NULL,expires_at BIGINT NOT NULL,revoked_at BIGINT NOT NULL DEFAULT 0,revoked_reason VARCHAR(64))",
    ] {
        sqlx::query(ddl).execute(&pool).await.expect("fixture DDL");
    }
    let db = Database::Sqlite(pool);
    let auth = SessionAuth::without_cache(db.clone(), AuthKeys::new("fixture-session-secret"));
    (db, auth)
}

struct TerminalFailure;

impl newapi_identity::sessions::RevocationFence for TerminalFailure {
    async fn revoking(
        &self,
        _: &newapi_identity::sessions::SessionMetadata,
        _: i64,
        _: &str,
    ) -> Result<(), newapi_identity::sessions::SessionError> {
        Ok(())
    }

    async fn revoked(
        &self,
        _: &newapi_identity::sessions::SessionMetadata,
        _: i64,
    ) -> Result<(), newapi_identity::sessions::SessionError> {
        Err(newapi_identity::sessions::SessionError::Fence)
    }
}

#[tokio::test]
async fn committed_logout_preserves_terminal_failure_observability() {
    let (db, _) = fixture().await;
    let first = credential();
    seed(&db, &first).await;
    let auth = SessionAuth::new(
        db.clone(),
        AuthKeys::new("fixture-session-secret"),
        TerminalFailure,
    );
    auth.logout(Some(first.raw().expose_secret()), None, NOW + 1)
        .await
        .expect("已提交撤销不伪造回滚");
    assert_eq!(auth.terminal_fence_failures(), 1);
    let record = SessionRepository::new(db.clone())
        .authoritative(first.sid())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.metadata.status, "revoked");
    db.close().await;
}

#[tokio::test]
async fn bearer_revoke_and_refresh_reuse_preserve_terminal_failures() {
    let (db, _) = fixture().await;
    let auth = SessionAuth::new(
        db.clone(),
        AuthKeys::new("fixture-session-secret"),
        TerminalFailure,
    );
    let bearer_session = credential();
    seed(&db, &bearer_session).await;
    auth.revoke_session(
        &newapi_identity::AuthIdentity {
            user_id: 1,
            sid: bearer_session.sid().into(),
            user_auth_version: 3,
            session_version: 1,
        },
        NOW + 1,
    )
    .await
    .expect("撤销已提交");
    assert_eq!(auth.terminal_fence_failures(), 1);

    let reused = credential();
    seed(&db, &reused).await;
    auth.refresh(reused.raw().expose_secret(), None, NOW + 1)
        .await
        .expect("首次刷新");
    assert_eq!(
        auth.refresh(reused.raw().expose_secret(), None, NOW + 32)
            .await
            .err(),
        Some(SessionAuthError::Unauthorized),
    );
    assert_eq!(auth.terminal_fence_failures(), 2);
    for sid in [bearer_session.sid(), reused.sid()] {
        let record = SessionRepository::new(db.clone())
            .authoritative(sid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.metadata.status, "revoked");
    }
    db.close().await;
}

#[tokio::test]
async fn session_management_scopes_revocation_to_the_authenticated_user() {
    let (db, auth) = fixture().await;
    let current = credential();
    let other = credential();
    seed(&db, &current).await;
    seed(&db, &other).await;
    let identity = newapi_identity::AuthIdentity {
        user_id: 1,
        sid: current.sid().into(),
        user_auth_version: 3,
        session_version: 1,
    };
    let foreign = newapi_identity::AuthIdentity {
        user_id: 2,
        sid: "foreign-session".into(),
        user_auth_version: 1,
        session_version: 1,
    };
    assert!(
        !auth
            .revoke_sid(&foreign, other.sid(), NOW + 1)
            .await
            .unwrap()
    );
    assert_eq!(
        auth.revoke_sid(&identity, "  ", NOW + 1).await.err(),
        Some(SessionAuthError::SessionIdRequired),
    );
    assert_eq!(auth.revoke_others(&identity, NOW + 1).await.unwrap(), 1);
    auth.validate(&identity, NOW + 2)
        .await
        .expect("保留当前会话");
    assert!(
        !auth
            .revoke_sid(&identity, other.sid(), NOW + 2)
            .await
            .unwrap()
    );
    assert!(
        auth.revoke_sid(&identity, current.sid(), NOW + 2)
            .await
            .unwrap()
    );
    assert_eq!(
        auth.validate(&identity, NOW + 3).await.err(),
        Some(SessionAuthError::Unauthorized),
    );
    db.close().await;
}

fn digest(key: &AuthKeys, secret: &str) -> RefreshHash {
    let value = key.refresh_hash(secret).expose_secret().to_owned();
    RefreshHash::from_lower_hex(value).expect("digest")
}

async fn seed(db: &Database, credential: &RefreshCredential) {
    let keys = AuthKeys::new("fixture-session-secret");
    SessionRepository::new(db.clone())
        .create(
            CreateSession {
                sid: credential.sid().into(),
                user_id: 1,
                expected_auth_version: Some(3),
                refresh_hash: digest(&keys, credential.secret()),
                login_method: "password".into(),
                ip: "127.0.0.1".into(),
                user_agent: "agent".into(),
            },
            SessionLimits::default(),
            NOW,
        )
        .await
        .expect("seed session");
}

fn credential() -> RefreshCredential {
    let generated = RefreshCredential::generate().expect("credential");
    RefreshCredential::parse(generated.raw().expose_secret()).expect("parse generated")
}

struct PendingFailure;

impl newapi_identity::sessions::RevocationFence for PendingFailure {
    async fn revoking(
        &self,
        _: &newapi_identity::sessions::SessionMetadata,
        _: i64,
        _: &str,
    ) -> Result<(), newapi_identity::sessions::SessionError> {
        Err(newapi_identity::sessions::SessionError::Fence)
    }

    async fn revoked(
        &self,
        _: &newapi_identity::sessions::SessionMetadata,
        _: i64,
    ) -> Result<(), newapi_identity::sessions::SessionError> {
        panic!("pending fence 失败后不得进入终态 fence");
    }
}

#[tokio::test]
async fn current_refresh_after_auth_version_change_preserves_terminal_failure() {
    let (db, _) = fixture().await;
    let first = credential();
    seed(&db, &first).await;
    let auth = SessionAuth::new(
        db.clone(),
        AuthKeys::new("fixture-session-secret"),
        TerminalFailure,
    );
    let issued = auth
        .refresh(first.raw().expose_secret(), None, NOW + 1)
        .await
        .expect("取得当前有效 refresh");
    let current =
        RefreshCredential::parse(issued.refresh_token.expose_secret()).expect("解析当前 refresh");
    let repository = SessionRepository::new(db.clone());
    let before = repository
        .authoritative(first.sid())
        .await
        .expect("读取刷新后会话")
        .expect("会话存在");
    assert!(before.current_hash_matches(&digest(
        &AuthKeys::new("fixture-session-secret"),
        current.secret(),
    )));
    assert_eq!(before.metadata.status, "active");
    assert_eq!(auth.terminal_fence_failures(), 0);
    let Database::Sqlite(pool) = &db else {
        panic!("fixture 必须使用 SQLite");
    };
    let changed = sqlx::query("UPDATE users SET auth_version=auth_version+1 WHERE id=1")
        .execute(pool)
        .await
        .expect("变更用户安全版本");
    assert_eq!(changed.rows_affected(), 1);

    assert_eq!(
        auth.refresh(issued.refresh_token.expose_secret(), None, NOW + 2)
            .await
            .err(),
        Some(SessionAuthError::Unauthorized),
    );
    assert_eq!(auth.terminal_fence_failures(), 1);
    let after = repository
        .authoritative(first.sid())
        .await
        .expect("读取已提交撤销")
        .expect("保留会话行");
    assert_eq!(after.metadata.status, "revoked");
    assert_eq!(after.metadata.revoked_at, NOW + 2);
    assert_eq!(after.metadata.revoked_reason, "user_security_changed");
    db.close().await;
}

#[tokio::test]
async fn public_revoke_commits_despite_terminal_failure_and_keeps_count() {
    let (db, _) = fixture().await;
    let first = credential();
    seed(&db, &first).await;
    let auth = SessionAuth::new(
        db.clone(),
        AuthKeys::new("fixture-session-secret"),
        TerminalFailure,
    );
    let issued = auth
        .refresh(first.raw().expose_secret(), None, NOW + 1)
        .await
        .expect("签发旧 access");
    assert_eq!(auth.terminal_fence_failures(), 0);
    auth.revoke_session(&issued.access_identity, NOW + 2)
        .await
        .expect("终态 fence 失败不回滚已提交撤销");
    assert_eq!(auth.terminal_fence_failures(), 1);
    let repository = SessionRepository::new(db.clone());
    let committed = repository
        .authoritative(first.sid())
        .await
        .expect("读取已提交撤销")
        .expect("保留会话行");
    assert_eq!(committed.metadata.status, "revoked");
    assert_eq!(committed.metadata.revoked_at, NOW + 2);
    assert_eq!(committed.metadata.revoked_reason, "logout");
    assert_eq!(
        auth.identify(issued.access_token.expose_secret(), NOW + 3)
            .await
            .err(),
        Some(SessionAuthError::Unauthorized),
    );
    auth.revoke_session(&issued.access_identity, NOW + 4)
        .await
        .expect("重复撤销幂等成功");
    assert_eq!(auth.terminal_fence_failures(), 1);
    let repeated = repository
        .authoritative(first.sid())
        .await
        .expect("读取重复撤销结果")
        .expect("保留会话行");
    assert_eq!(repeated.metadata, committed.metadata);
    db.close().await;
}

#[tokio::test]
async fn pending_fence_failure_leaves_sql_and_old_access_active() {
    let (db, _) = fixture().await;
    let first = credential();
    seed(&db, &first).await;
    let auth = SessionAuth::new(
        db.clone(),
        AuthKeys::new("fixture-session-secret"),
        PendingFailure,
    );
    let issued = auth
        .refresh(first.raw().expose_secret(), None, NOW + 1)
        .await
        .expect("签发旧 access");
    let repository = SessionRepository::new(db.clone());
    let before = repository
        .authoritative(first.sid())
        .await
        .expect("读取撤销前状态")
        .expect("会话存在");
    assert_eq!(before.metadata.status, "active");
    assert_eq!(before.metadata.revoked_at, 0);
    assert_eq!(auth.terminal_fence_failures(), 0);
    assert_eq!(
        auth.identify(issued.access_token.expose_secret(), NOW + 2)
            .await
            .expect("撤销前 access 有效"),
        issued.access_identity,
    );

    assert_eq!(
        auth.revoke_session(&issued.access_identity, NOW + 3)
            .await
            .err(),
        Some(SessionAuthError::Fence),
    );
    assert_eq!(auth.terminal_fence_failures(), 0);
    let after = repository
        .authoritative(first.sid())
        .await
        .expect("读取 pending 失败后的 SQL 状态")
        .expect("保留会话行");
    assert_eq!(after.metadata, before.metadata);
    let current =
        RefreshCredential::parse(issued.refresh_token.expose_secret()).expect("解析当前 refresh");
    assert!(after.current_hash_matches(&digest(
        &AuthKeys::new("fixture-session-secret"),
        current.secret(),
    )));
    assert_eq!(
        auth.identify(issued.access_token.expose_secret(), NOW + 4)
            .await
            .expect("pending fence 失败后旧 access 仍有效"),
        issued.access_identity,
    );
    assert_eq!(auth.terminal_fence_failures(), 0);
    db.close().await;
}

#[tokio::test]
async fn identify_rejects_disabled_and_soft_deleted_users_without_storage_classification() {
    for column in ["status", "deleted_at"] {
        let (db, auth) = fixture().await;
        let first = credential();
        seed(&db, &first).await;
        let issued = auth
            .refresh(first.raw().expose_secret(), None, NOW + 1)
            .await
            .expect("签发有效 access");
        let Database::Sqlite(pool) = &db else {
            panic!("fixture 必须使用 SQLite");
        };
        let query = match column {
            "status" => "UPDATE users SET status=0 WHERE id=1",
            "deleted_at" => "UPDATE users SET deleted_at=1 WHERE id=1",
            _ => unreachable!(),
        };
        sqlx::query(query).execute(pool).await.expect("更新用户状态");
        assert_eq!(
            auth.identify(issued.access_token.expose_secret(), NOW + 2)
                .await
                .err(),
            Some(SessionAuthError::Unauthorized),
        );
        db.close().await;
    }
}

#[tokio::test]
async fn identify_rejects_expired_or_malformed_access_as_unauthorized() {
    let (db, auth) = fixture().await;
    let first = credential();
    seed(&db, &first).await;
    let issued = auth
        .refresh(first.raw().expose_secret(), None, NOW + 1)
        .await
        .expect("签发有效 access");
    assert_eq!(
        auth.identify(issued.access_token.expose_secret(), NOW + 901)
            .await
            .err(),
        Some(SessionAuthError::Unauthorized),
    );
    assert_eq!(
        auth.parse_access("not-a-jwt", NOW + 1).err(),
        Some(SessionAuthError::Unauthorized),
    );
    db.close().await;
}

#[tokio::test]
async fn identify_with_closed_sql_pool_preserves_storage_error() {
    let (db, auth) = fixture().await;
    let first = credential();
    seed(&db, &first).await;
    let issued = auth
        .refresh(first.raw().expose_secret(), None, NOW + 1)
        .await
        .expect("签发有效 access");
    assert_eq!(
        auth.identify(issued.access_token.expose_secret(), NOW + 2)
            .await
            .expect("关闭连接池前 access 有效"),
        issued.access_identity,
    );
    db.close().await;
    assert_eq!(
        auth.parse_access(issued.access_token.expose_secret(), NOW + 3)
            .expect("关闭 SQL 池不影响 access 验签"),
        issued.access_identity,
    );
    assert_eq!(
        auth.identify(issued.access_token.expose_secret(), NOW + 3)
            .await
            .err(),
        Some(SessionAuthError::Storage(
            newapi_identity::sessions::SessionError::Storage,
        )),
    );
    assert_eq!(auth.terminal_fence_failures(), 0);
}

#[tokio::test]
async fn refresh_rotates_and_validates() {
    let (db, auth) = fixture().await;
    let first = credential();
    seed(&db, &first).await;
    let result = auth
        .refresh(first.raw().expose_secret(), Some(first.sid()), NOW + 1)
        .await
        .expect("refresh");
    assert!(result.session.current);
    assert_eq!(result.access_expires_at, NOW + 1 + 900);
    let keys = AuthKeys::new("fixture-session-secret");
    let parsed = keys
        .parse_access(result.access_token.expose_secret(), NOW + 2)
        .expect("access parses");
    assert_eq!(parsed, result.access_identity);
    auth.validate(&parsed, NOW + 2)
        .await
        .expect("session active");
    db.close().await;
}

#[tokio::test]
async fn replay_within_grace_is_idempotent_and_swaps_cookie() {
    let (db, auth) = fixture().await;
    let first = credential();
    seed(&db, &first).await;
    let once = auth
        .refresh(first.raw().expose_secret(), None, NOW + 1)
        .await
        .expect("first refresh");
    let replay = auth
        .refresh(first.raw().expose_secret(), None, NOW + 5)
        .await
        .expect("grace replay");
    assert_eq!(
        once.refresh_token.expose_secret(),
        replay.refresh_token.expose_secret()
    );
    assert_eq!(replay.access_expires_at, NOW + 5 + 900);
    db.close().await;
}

#[tokio::test]
async fn replay_after_grace_revokes_family() {
    let (db, auth) = fixture().await;
    let first = credential();
    seed(&db, &first).await;
    auth.refresh(first.raw().expose_secret(), None, NOW + 1)
        .await
        .expect("first refresh");
    assert_eq!(
        auth.refresh(first.raw().expose_secret(), None, NOW + 100)
            .await
            .err(),
        Some(SessionAuthError::Unauthorized)
    );
    assert!(matches!(
        auth.validate(
            &newapi_identity::AuthIdentity {
                user_id: 1,
                sid: first.sid().into(),
                user_auth_version: 3,
                session_version: 1,
            },
            NOW + 101
        )
        .await,
        Err(SessionAuthError::Unauthorized)
    ));
    db.close().await;
}

#[tokio::test]
async fn logout_is_idempotent_and_hides_existence() {
    let (db, auth) = fixture().await;
    let first = credential();
    seed(&db, &first).await;
    auth.logout(Some(first.raw().expose_secret()), None, NOW + 1)
        .await
        .expect("logout");
    auth.logout(Some(first.raw().expose_secret()), None, NOW + 2)
        .await
        .expect("second logout");
    auth.logout(None, None, NOW + 3).await.expect("no cookie");
    let unknown = credential();
    auth.logout(Some(unknown.raw().expose_secret()), None, NOW + 4)
        .await
        .expect("unknown session");
    assert_eq!(
        auth.refresh(first.raw().expose_secret(), None, NOW + 5)
            .await
            .err(),
        Some(SessionAuthError::Unauthorized)
    );
    db.close().await;
}

#[tokio::test]
async fn sid_mismatch_is_rejected() {
    let (db, auth) = fixture().await;
    let first = credential();
    seed(&db, &first).await;
    assert_eq!(
        auth.refresh(
            first.raw().expose_secret(),
            Some("ffffffff-ffff-4fff-8fff-ffffffffffff"),
            NOW + 1
        )
        .await
        .err(),
        Some(SessionAuthError::SessionMismatch)
    );
    db.close().await;
}
