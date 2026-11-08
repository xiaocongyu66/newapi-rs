//! 绑定码生命周期与解绑事务的单元测试（内存 SQLite）。
//!
//! 双后端契约（同样的语义在 PostgreSQL 上再跑一遍）在
//! `apps/server/tests/qq_bind_routes.rs`。

use super::{
    BIND_CODE_ALPHABET, BIND_CODE_ATTEMPTS, BIND_CODE_LENGTH, BIND_CODE_TTL_SECONDS,
    QQBindCodeError, QQBindingRepository, QQUnbindError,
};
use newapi_storage::Database;
use sqlx::sqlite::SqlitePoolOptions;

const BINDINGS: &str = r#"CREATE TABLE qq_bindings (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    open_id TEXT NOT NULL,
    username TEXT,
    created_at INTEGER
)"#;

const CODES: &str = r#"CREATE TABLE qq_bind_codes (
    id INTEGER PRIMARY KEY,
    code TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    expired_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER
)"#;

const UNBIND_RECORDS: &str = r#"CREATE TABLE qq_unbind_records (
    user_id INTEGER PRIMARY KEY,
    unbind_at INTEGER NOT NULL,
    created_at INTEGER
)"#;

async fn repository() -> QQBindingRepository {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite");
    sqlx::query(BINDINGS)
        .execute(&pool)
        .await
        .expect("bindings");
    sqlx::query(CODES).execute(&pool).await.expect("codes");
    sqlx::query(UNBIND_RECORDS)
        .execute(&pool)
        .await
        .expect("unbind records");
    QQBindingRepository::new(Database::Sqlite(pool))
}

/// 单元测试只跑内存 SQLite；取回池用于种子数据与断言。
fn pool_of(repository: &QQBindingRepository) -> &sqlx::SqlitePool {
    match &repository.db {
        Database::Sqlite(pool) => pool,
        Database::Postgres(_) => unreachable!("unit tests use in-memory SQLite"),
    }
}

async fn seed_binding(repository: &QQBindingRepository, user_id: i64, username: &str) {
    let pool = pool_of(repository);
    sqlx::query(
        "INSERT INTO qq_bindings (user_id, open_id, username, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind("OPENID")
    .bind(username)
    .bind(1_700_000_000)
    .execute(pool)
    .await
    .expect("seed binding");
}

async fn seed_unbind_record(repository: &QQBindingRepository, user_id: i64, unbind_at: i64) {
    let pool = pool_of(repository);
    sqlx::query(
        "INSERT INTO qq_unbind_records (user_id, unbind_at, created_at) VALUES ($1, $2, $3)",
    )
    .bind(user_id)
    .bind(unbind_at)
    .bind(unbind_at)
    .execute(pool)
    .await
    .expect("seed unbind record");
}

async fn all_codes(repository: &QQBindingRepository, user_id: i64) -> Vec<(String, i64, i64)> {
    let pool = pool_of(repository);
    sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT code, used, expired_at FROM qq_bind_codes WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .expect("codes of user")
}

async fn binding_rows(repository: &QQBindingRepository, user_id: i64) -> i64 {
    let pool = pool_of(repository);
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM qq_bindings WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("binding rows")
}

async fn unbind_records(repository: &QQBindingRepository, user_id: i64) -> Vec<(i64, i64)> {
    let pool = pool_of(repository);
    sqlx::query_as::<_, (i64, i64)>(
        "SELECT unbind_at, created_at FROM qq_unbind_records WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .expect("unbind records of user")
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

#[test]
fn alphabet_drops_the_ambiguous_characters() {
    assert_eq!(BIND_CODE_ALPHABET.len(), 56);
    for byte in BIND_CODE_ALPHABET {
        assert!(byte.is_ascii_alphanumeric(), "{byte} must be alphanumeric");
    }
    // Go `bindCodeAlphabet` 去掉了 0/O/o 与 1/l/I。
    for ambiguous in *b"0Oo1lI" {
        assert!(
            !BIND_CODE_ALPHABET.contains(&ambiguous),
            "{} must not be in the alphabet",
            ambiguous as char
        );
    }
    // 数字只剩 2-9，字母大小写各 24 个。
    assert_eq!(
        BIND_CODE_ALPHABET
            .iter()
            .filter(|byte| byte.is_ascii_digit())
            .count(),
        8
    );
    assert_eq!(
        BIND_CODE_ALPHABET
            .iter()
            .filter(|byte| byte.is_ascii_uppercase())
            .count(),
        24
    );
    assert_eq!(
        BIND_CODE_ALPHABET
            .iter()
            .filter(|byte| byte.is_ascii_lowercase())
            .count(),
        24
    );
    assert_eq!(BIND_CODE_LENGTH, 6);
    assert_eq!(BIND_CODE_ATTEMPTS, 8);
    assert_eq!(BIND_CODE_TTL_SECONDS, 300);
}

#[tokio::test]
async fn create_bind_code_issues_a_prefixed_code_with_the_ttl() {
    let repository = repository().await;
    let before = now();
    let code = repository.create_bind_code(7, 0).await.expect("code");
    assert!(code.code.starts_with('#'), "{}", code.code);
    assert_eq!(code.code.chars().count(), 7, "{}", code.code);
    for character in code.code.chars().skip(1) {
        assert!(
            (BIND_CODE_ALPHABET as &[u8]).contains(&(character as u8)),
            "{character} outside the alphabet"
        );
    }
    let after = now();
    assert!(
        (before + BIND_CODE_TTL_SECONDS..=after + BIND_CODE_TTL_SECONDS).contains(&code.expired_at),
        "expired_at {} outside the TTL window",
        code.expired_at
    );
    let rows = all_codes(&repository, 7).await;
    assert_eq!(rows, vec![(code.code.clone(), 0, code.expired_at)]);
}

#[tokio::test]
async fn regenerate_invalidates_the_previous_unused_code() {
    let repository = repository().await;
    let first = repository.create_bind_code(7, 0).await.expect("first code");
    let second = repository
        .create_bind_code(7, 0)
        .await
        .expect("second code");
    // Go `qq_binding.go:182-184`：重复调用作废此前未使用的验证码。
    let rows = all_codes(&repository, 7).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    let first_row = rows
        .iter()
        .find(|(code, _, _)| *code == first.code)
        .expect("first code row");
    assert_eq!(first_row.1, 1, "the previous code must be invalidated");
    let second_row = rows
        .iter()
        .find(|(code, _, _)| *code == second.code)
        .expect("second code row");
    assert_eq!(second_row.1, 0, "the new code must stay usable");
}

#[tokio::test]
async fn bound_user_cannot_generate_a_code() {
    let repository = repository().await;
    seed_binding(&repository, 7, "杰瑞").await;
    assert_eq!(
        repository.create_bind_code(7, 0).await,
        Err(QQBindCodeError::AlreadyBound)
    );
    assert!(all_codes(&repository, 7).await.is_empty());
}

#[tokio::test]
async fn cooldown_blocks_regeneration_and_reports_the_remaining_seconds() {
    let repository = repository().await;
    seed_unbind_record(&repository, 7, now()).await;
    match repository.create_bind_code(7, 3600).await {
        Err(QQBindCodeError::Cooldown { remaining_seconds }) => {
            // 生成时刻与断言时刻可能跨过一秒，只锁区间。
            assert!(
                (3590..=3600).contains(&remaining_seconds),
                "unexpected remaining seconds {remaining_seconds}"
            );
        }
        other => panic!("expected a cooldown rejection, got {other:?}"),
    }
    assert!(all_codes(&repository, 7).await.is_empty());

    // 冷却关闭（<= 0）后放行。
    let code = repository
        .create_bind_code(7, 0)
        .await
        .expect("cooldown off");
    assert!(code.code.starts_with('#'));
}

#[tokio::test]
async fn an_expired_cooldown_lets_the_user_rebind() {
    let repository = repository().await;
    seed_unbind_record(&repository, 7, now() - 3601).await;
    let code = repository.create_bind_code(7, 3600).await.expect("code");
    assert!(code.code.starts_with('#'));
}

#[tokio::test]
async fn bind_status_reports_username_and_created_at() {
    let repository = repository().await;
    assert_eq!(repository.bind_status(7).await, None);
    seed_binding(&repository, 7, "杰瑞").await;
    let status = repository.bind_status(7).await.expect("bound");
    assert_eq!(status.username, "杰瑞");
    assert_eq!(status.bound_at, 1_700_000_000);
}

#[tokio::test]
async fn bind_status_keeps_empty_username_as_an_empty_string() {
    let repository = repository().await;
    // 空串原样返回；NULL 列的同一归零路径由 `apps/server/tests/qq_bind_routes.rs`
    // 的 NULL 种子覆盖（那里绑 `Option<&str>`）。
    seed_binding(&repository, 7, "").await;
    let status = repository.bind_status(7).await.expect("bound");
    assert_eq!(status.username, "");
}

#[tokio::test]
async fn unbind_removes_the_binding_every_code_and_records_the_time() {
    let repository = repository().await;
    // 绑定行存在时 CreateQQBindCode 会直接拒绝，所以先拿码再补绑定行。
    let unused = repository.create_bind_code(7, 0).await.expect("code");
    seed_binding(&repository, 7, "杰瑞").await;
    // 再放一个已使用的行：Go 的删除不带 `used` 过滤，两类都要清。
    let pool = pool_of(&repository);
    sqlx::query(
        "INSERT INTO qq_bind_codes (code, user_id, expired_at, used, created_at)
         VALUES ('#Used99', 7, 1, 1, 1)",
    )
    .execute(pool)
    .await
    .expect("seed used code");

    let before = now();
    repository.delete_binding(7).await.expect("unbind");
    assert_eq!(binding_rows(&repository, 7).await, 0);
    assert!(all_codes(&repository, 7).await.is_empty());
    let records = unbind_records(&repository, 7).await;
    assert_eq!(records.len(), 1);
    assert!(records[0].0 >= before, "unbind_at must be fresh");
    // 未使用的码已作废，ConsumeQQBindCode 再也不能用它绑回来。
    assert!(unused.code.starts_with('#'));

    // 解绑记录是 upsert：再次解绑只更新同一行。
    repository.delete_binding(7).await.expect("unbind again");
    assert_eq!(unbind_records(&repository, 7).await.len(), 1);
}

#[tokio::test]
async fn unbind_of_a_never_bound_user_succeeds() {
    let repository = repository().await;
    // Go 的删除匹配零行也不报错（`qq_binding.go:304-310`）。
    repository.delete_binding(7).await.expect("unbind");
    let records = unbind_records(&repository, 7).await;
    assert_eq!(records.len(), 1);
}

#[tokio::test]
async fn unbind_rejects_the_zero_user_id() {
    let repository = repository().await;
    assert_eq!(
        repository.delete_binding(0).await,
        Err(QQUnbindError::EmptyUserId)
    );
}
