//! 令牌 Redis 缓存契约测试：真实 Redis + 内存 SQLite 仓储。
//! TEST_REDIS_URL 缺失必须失败，禁止静默跳过（与 `redis_cache.rs` 同一约定）。
//! 只操作随机令牌键对应的 Redis 键，不清空数据库，不打印连接配置或明文键。
use std::sync::Arc;

use hmac::{Hmac, Mac};
use newapi_identity::token_cache::{
    IO_TIMEOUT, RedisTokenCache, TOKEN_CACHE_FENCE_SECONDS, TokenCacheInit,
};
use newapi_identity::tokens::{NewToken, TokenRecord, TokenRepository};
use newapi_storage::Database;
use redis::aio::MultiplexedConnection;
use sha2::Sha256;
use sqlx::sqlite::SqlitePoolOptions;

const SECRET: &[u8] = b"token-cache-contract-secret-not-for-production";

/// 与 Go `common.GenerateHMAC` 同算法：HMAC-SHA256(secret, key) 的十六进制。
fn expected_hmac(key: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(SECRET).expect("HMAC key");
    mac.update(key.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8] = b"0123456789abcdef";
    for byte in bytes {
        hex.push(HEX[(byte >> 4) as usize] as char);
        hex.push(HEX[(byte & 15) as usize] as char);
    }
    hex
}

fn unique_key(tag: &str) -> String {
    format!("tc-{tag}-{}-{:016x}", std::process::id(), random_u128())
}

fn random_u128() -> u128 {
    // 与 `redis_cache.rs` 同源的随机后缀，避免并行/重复运行共享 Redis 互相污染。
    rand::random::<u128>()
}

async fn control_connection() -> MultiplexedConnection {
    let url =
        std::env::var("TEST_REDIS_URL").expect("令牌缓存契约测试必须设置 TEST_REDIS_URL，禁止跳过");
    let client = redis::Client::open(url)
        .unwrap_or_else(|_| panic!("TEST_REDIS_URL 必须是有效的 Redis 测试配置"));
    tokio::time::timeout(IO_TIMEOUT, client.get_multiplexed_async_connection())
        .await
        .unwrap_or_else(|_| panic!("真实 Redis 测试连接超时"))
        .unwrap_or_else(|_| panic!("无法连接真实 Redis；请检查测试配置"))
}

async fn cache(seconds: i64) -> Arc<RedisTokenCache> {
    let connection = control_connection().await;
    Arc::new(
        RedisTokenCache::from_connection(connection, SECRET, seconds)
            .expect("令牌缓存构造受限于空密钥或非法 TTL"),
    )
}

async fn exists(control: &mut MultiplexedConnection, key: &str) -> i64 {
    tokio::time::timeout(
        IO_TIMEOUT,
        redis::cmd("EXISTS").arg(key).query_async(control),
    )
    .await
    .expect("Redis EXISTS 超时")
    .unwrap_or_else(|_| panic!("Redis EXISTS 失败"))
}

async fn ttl_seconds(control: &mut MultiplexedConnection, key: &str) -> i64 {
    tokio::time::timeout(IO_TIMEOUT, redis::cmd("TTL").arg(key).query_async(control))
        .await
        .expect("Redis TTL 超时")
        .unwrap_or_else(|_| panic!("Redis TTL 失败"))
}

async fn cleanup(control: &mut MultiplexedConnection, key: &str) {
    let _: i64 = tokio::time::timeout(IO_TIMEOUT, redis::cmd("DEL").arg(key).query_async(control))
        .await
        .expect("测试键清理超时")
        .unwrap_or_else(|_| panic!("测试键清理失败"));
}

fn token_record(id: i64, key: &str) -> TokenRecord {
    TokenRecord {
        id,
        user_id: 7,
        key: key.to_owned(),
        status: 1,
        name: "contract".to_owned(),
        created_time: 100,
        accessed_time: 200,
        expired_time: -1,
        remain_quota: 500_000,
        // INSERT 固定写 0；与仓储读取的预期保持一致。
        used_quota: 0,
        unlimited_quota: false,
        model_limits_enabled: true,
        model_limits: "gpt-4o".to_owned(),
        allow_ips: Some("1.2.3.4".to_owned()),
        group: "default".to_owned(),
        cross_group_retry: true,
        auto_groups: r#"["default"]"#.to_owned(),
    }
}

const SQLITE_TOKENS: &str = r#"CREATE TABLE tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id BIGINT NOT NULL,
    "key" TEXT NOT NULL UNIQUE,
    status INTEGER NOT NULL DEFAULT 1,
    name TEXT NOT NULL DEFAULT '',
    created_time BIGINT NOT NULL DEFAULT 0,
    accessed_time BIGINT NOT NULL DEFAULT 0,
    expired_time BIGINT NOT NULL DEFAULT -1,
    remain_quota BIGINT NOT NULL DEFAULT 0,
    used_quota BIGINT NOT NULL DEFAULT 0,
    unlimited_quota INTEGER NOT NULL DEFAULT 0,
    model_limits_enabled INTEGER NOT NULL DEFAULT 0,
    model_limits TEXT NOT NULL DEFAULT '',
    allow_ips TEXT,
    "group" TEXT NOT NULL DEFAULT '',
    cross_group_retry INTEGER NOT NULL DEFAULT 0,
    auto_groups TEXT NOT NULL DEFAULT '',
    deleted_at TIMESTAMP
)"#;

async fn sqlite_repository(cache: Option<Arc<RedisTokenCache>>) -> TokenRepository {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    sqlx::query(SQLITE_TOKENS)
        .execute(&pool)
        .await
        .expect("tokens fixture");
    let db = Database::Sqlite(pool);
    match cache {
        Some(cache) => TokenRepository::new(db).with_token_cache(cache),
        None => TokenRepository::new(db),
    }
}

async fn insert_token(repository: &TokenRepository, user_id: i64, key: &str) -> i64 {
    repository
        .insert(&NewToken {
            user_id,
            key: key.to_owned(),
            name: "contract".to_owned(),
            created_time: 100,
            accessed_time: 200,
            expired_time: -1,
            remain_quota: 500_000,
            unlimited_quota: false,
            model_limits_enabled: true,
            model_limits: "gpt-4o".to_owned(),
            allow_ips: Some("1.2.3.4".to_owned()),
            group: "default".to_owned(),
            cross_group_retry: true,
            auto_groups: r#"["default"]"#.to_owned(),
        })
        .await
        .expect("seed token")
}

async fn is_soft_deleted(repository: &TokenRepository, key: &str) -> bool {
    // `by_key` 的默认作用域已过滤软删行；命中即未删。
    repository
        .by_key(key)
        .await
        .map(|token| token.is_none())
        .unwrap_or(true)
}

#[tokio::test]
async fn redis_key_derivation_matches_hmac_of_the_raw_key() {
    let cache = cache(60).await;
    let key = unique_key("derive");
    let hash = cache.cache_key(&key);
    let fence = cache.fence_key(&key);
    assert_eq!(hash, format!("token:{}", expected_hmac(&key)));
    assert_eq!(fence, format!("token:fence:{}", expected_hmac(&key)));
    assert!(!hash.contains(&key), "明文键不得出现在 Redis 键里");
}

#[tokio::test]
async fn redis_init_publishes_get_reads_and_refresh_does_not_overwrite() {
    let cache = cache(7).await;
    let mut control = control_connection().await;
    let key = unique_key("roundtrip");
    let record = token_record(11, &key);
    assert_eq!(cache.init(&record).await, Ok(TokenCacheInit::Initialized));
    // TTL 受构造时传入的秒数约束。
    let data_key = cache.cache_key(&key);
    let ttl = ttl_seconds(&mut control, &data_key).await;
    assert!(ttl > 0 && ttl <= 7, "TTL 必须落在配置的 7 秒内，实际 {ttl}");
    let cached = cache.get_by_key(&key).await.expect("读取已初始化的哈希");
    assert_eq!(cached, Some(record.clone()));
    // 已存在的哈希仅续期，快照不得覆盖任何字段。
    let mut ahead = record.clone();
    ahead.remain_quota = 999_999;
    ahead.name = "mutated-by-relay".to_owned();
    assert_eq!(cache.init(&ahead).await, Ok(TokenCacheInit::Refreshed));
    let still = cache.get_by_key(&key).await.expect("读取续期后的哈希");
    assert_eq!(still, Some(record), "续期不得改写既有字段");
    cleanup(&mut control, &data_key).await;
    cleanup(&mut control, &cache.fence_key(&key)).await;
}

#[tokio::test]
async fn redis_invalidate_raises_fence_blocks_init_and_drops_hash() {
    let cache = cache(60).await;
    let mut control = control_connection().await;
    let key = unique_key("invalidate");
    let data_key = cache.cache_key(&key);
    let fence_key = cache.fence_key(&key);
    assert_eq!(
        cache.init(&token_record(12, &key)).await,
        Ok(TokenCacheInit::Initialized)
    );
    cache.invalidate_for_mutation(&key).await.expect("失效成功");
    assert_eq!(exists(&mut control, &data_key).await, 0, "哈希必须删除");
    assert!(
        ttl_seconds(&mut control, &fence_key).await > 0
            && ttl_seconds(&mut control, &fence_key).await <= TOKEN_CACHE_FENCE_SECONDS,
        "栅栏存在且不超过 {} 秒",
        TOKEN_CACHE_FENCE_SECONDS
    );
    assert_eq!(
        cache.get_by_key(&key).await,
        Ok(None),
        "哈希删除后读取必须落空"
    );
    // 栅栏存在时初始化被拦截：阻止在途读者回填变更前快照。
    assert_eq!(
        cache.init(&token_record(12, &key)).await,
        Ok(TokenCacheInit::Blocked)
    );
    // 空键是 Go 的直通分支。
    cache
        .invalidate_for_mutation("")
        .await
        .expect("空键不得产生 Redis 调用");
    cleanup(&mut control, &fence_key).await;
}

#[tokio::test]
async fn redis_incomplete_hash_is_a_miss() {
    let cache = cache(60).await;
    let mut control = control_connection().await;
    let key = unique_key("incomplete");
    let data_key = cache.cache_key(&key);
    // 仅有配额字段的残缺哈希（原子预扣脚本未命中时的形态）必须被拒绝。
    let _: () = tokio::time::timeout(
        IO_TIMEOUT,
        redis::cmd("HSET")
            .arg(&data_key)
            .arg("RemainQuota")
            .arg("5")
            .query_async(&mut control),
    )
    .await
    .expect("Redis HSET 超时")
    .expect("Redis HSET 失败");
    assert_eq!(cache.get_by_key(&key).await, Ok(None));
    cleanup(&mut control, &data_key).await;
}

#[tokio::test]
async fn redis_invalidate_many_skips_empty_keys() {
    let cache = cache(60).await;
    let mut control = control_connection().await;
    let first = unique_key("many1");
    let second = unique_key("many2");
    for key in [&first, &second] {
        assert_eq!(
            cache.init(&token_record(13, key)).await,
            Ok(TokenCacheInit::Initialized)
        );
    }
    // 与 Go `invalidateTokensCache` 一致：空键跳过，其余全部失效。
    cache
        .invalidate_many(&[first.clone(), String::new(), second.clone()])
        .await
        .expect("批量失效成功");
    for key in [&first, &second] {
        assert_eq!(exists(&mut control, &cache.cache_key(key)).await, 0);
        assert!(ttl_seconds(&mut control, &cache.fence_key(key)).await > 0);
        cleanup(&mut control, &cache.fence_key(key)).await;
    }
}

#[tokio::test]
async fn repository_caches_by_key_and_invalidates_on_delete() {
    let cache = cache(60).await;
    let mut control = control_connection().await;
    let repository = sqlite_repository(Some(cache.clone())).await;
    let key = unique_key("repo-delete");
    let id = insert_token(&repository, 7, &key).await;
    let data_key = cache.cache_key(&key);
    let fence_key = cache.fence_key(&key);

    // 冷读：缓存未命中 → 回源 → 用数据库快照初始化。
    let cold = repository.by_key_cached(&key).await.expect("冷读成功");
    assert_eq!(cold, Some(token_record(id, &key)));
    assert_eq!(exists(&mut control, &data_key).await, 1, "哈希应已初始化");
    // 命中：第二次读取走缓存（与数据库一致性由其它断言覆盖）。
    let hit = repository.by_key_cached(&key).await.expect("缓存读成功");
    assert_eq!(hit, Some(token_record(id, &key)));

    // Go `Token.Delete`：删前失效 → 栅栏 + 删哈希。
    assert!(repository.delete_for_user(7, id).await.expect("软删除成功"));
    assert_eq!(exists(&mut control, &data_key).await, 0);
    assert!(ttl_seconds(&mut control, &fence_key).await > 0);
    // sqlx::Error 不实现 PartialEq，不能整体 assert_eq。
    let after = repository
        .by_key_cached(&key)
        .await
        .expect("删除后读取成功");
    assert!(
        after.is_none(),
        "软删行对缓存读与库读都不可见，实际 {after:?}"
    );
    cleanup(&mut control, &fence_key).await;
}

#[tokio::test]
async fn repository_batch_delete_counts_only_own_tokens_and_invalidates() {
    let cache = cache(60).await;
    let mut control = control_connection().await;
    let repository = sqlite_repository(Some(cache.clone())).await;
    let own = unique_key("batch-own");
    let other = unique_key("batch-other");
    let own_id = insert_token(&repository, 7, &own).await;
    let other_id = insert_token(&repository, 8, &other).await;

    // 他人的 id 与不存在的 id 都不计入；删除是单事务全有全无。
    let count = repository
        .delete_many_for_user(7, &[own_id, other_id, own_id + other_id + 100])
        .await
        .expect("批量删除成功");
    assert_eq!(count, 1, "只删除该用户自己的令牌");
    assert!(is_soft_deleted(&repository, &own).await);
    assert!(!is_soft_deleted(&repository, &other).await);

    // 批量删除已在事务内置栅栏：缓存哈希删除且初始化被拦截。
    let data_key = cache.cache_key(&own);
    let fence_key = cache.fence_key(&own);
    assert_eq!(exists(&mut control, &data_key).await, 0);
    assert_eq!(
        cache.init(&token_record(own_id, &own)).await,
        Ok(TokenCacheInit::Blocked)
    );
    cleanup(&mut control, &fence_key).await;
}

#[tokio::test]
async fn repository_invalidate_user_tokens_cache_covers_soft_deleted_rows() {
    let cache = cache(60).await;
    let mut control = control_connection().await;
    let repository = sqlite_repository(Some(cache.clone())).await;
    let live = unique_key("user-live");
    let dead = unique_key("user-dead");
    let dead_id = insert_token(&repository, 9, &dead).await;
    insert_token(&repository, 9, &live).await;

    let live_data = cache.cache_key(&live);
    let dead_data = cache.cache_key(&dead);
    for key in [&live, &dead] {
        assert_eq!(
            cache.init(&token_record(1, key)).await,
            Ok(TokenCacheInit::Initialized)
        );
    }
    // 先软删一个，再整体失效（Go `Unscoped` 读取含软删行）。
    assert!(
        repository
            .delete_for_user(9, dead_id)
            .await
            .expect("软删除成功")
    );
    repository
        .invalidate_user_tokens_cache(9)
        .await
        .expect("用户级失效成功");
    for data_key in [live_data, dead_data] {
        assert_eq!(exists(&mut control, &data_key).await, 0, "全部键都应失效");
    }
    for key in [&live, &dead] {
        cleanup(&mut control, &cache.fence_key(key)).await;
    }
}

#[tokio::test]
async fn repository_without_cache_stays_database_only() {
    let mut control = control_connection().await;
    let cache = cache(60).await;
    let repository = sqlite_repository(None).await;
    let key = unique_key("db-only");
    let id = insert_token(&repository, 7, &key).await;

    // 未注入缓存等价于 Go `common.RedisEnabled=false`：纯数据库路径。
    let read = repository.by_key_cached(&key).await.expect("纯库读成功");
    assert_eq!(read, Some(token_record(id, &key)));
    let count = repository
        .delete_many_for_user(7, &[id])
        .await
        .expect("批量删除成功");
    assert_eq!(count, 1);
    assert_eq!(
        exists(&mut control, &cache.cache_key(&key)).await,
        0,
        "未注入缓存不得写 Redis"
    );
}
