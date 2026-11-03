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
        Some(SessionAuthError::SessionRevoked)
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
        Err(SessionAuthError::SessionRevoked)
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
        Some(SessionAuthError::SessionRevoked)
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
