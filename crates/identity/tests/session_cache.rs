//! 仅运行于显式配置的真实 Redis；环境缺失必须失败，不允许忽略或内存替代。
//! 集成者需先导出 sessions 与 session_cache 模块，并补齐精确依赖。
use std::collections::HashMap;

use newapi_identity::session_cache::{CacheError, CacheRead, FillOutcome, RedisSessionCache};
use newapi_identity::sessions::{RevocationFence, SessionError, SessionMetadata};
use redis::aio::MultiplexedConnection;

const SECRET: &[u8] = b"synthetic-session-cache-secret-not-for-production";

async fn connections(seconds: i64) -> (RedisSessionCache, RedisSessionCache, MultiplexedConnection) {
    let url = std::env::var("TEST_REDIS_URL")
        .expect("真实 Redis 测试必须设置 TEST_REDIS_URL，禁止跳过");
    let client = redis::Client::open(url).expect("测试 Redis URL 必须有效");
    let a = client.get_multiplexed_async_connection().await
        .expect("必须连接真实 Redis");
    let b = client.get_multiplexed_async_connection().await
        .expect("必须建立第二个独立 Redis 连接");
    let control = client.get_multiplexed_async_connection().await
        .expect("必须建立测试观察连接");
    (
        RedisSessionCache::from_connection(a, SECRET, seconds).unwrap(),
        RedisSessionCache::from_connection(b, SECRET, seconds).unwrap(),
        control,
    )
}

// 从真实 Redis 采样绝对时间；不假设测试机器与服务端的系统钟相同。
async fn now(connection: &mut MultiplexedConnection) -> i64 {
    let (seconds, micros): (i64, i64) = redis::cmd("TIME")
        .query_async(connection).await.unwrap();
    seconds * 1000 + micros / 1000
}

fn session(now_ms: i64) -> SessionMetadata {
    SessionMetadata {
        sid: format!("cache-test-{:032x}", rand::random::<u128>()),
        user_id: 42,
        version: 2,
        user_auth_version: 3,
        status: "active".into(),
        login_method: "password".into(),
        ip: "192.0.2.1".into(),
        user_agent: "合成测试客户端".into(),
        created_at: now_ms / 1000,
        last_active_at: now_ms / 1000,
        expires_at: now_ms / 1000 + 3600,
        revoked_at: 0,
        revoked_reason: String::new(),
    }
}

async fn ttl(connection: &mut MultiplexedConnection, key: &str) -> i64 {
    redis::cmd("PTTL").arg(key).query_async(connection).await.unwrap()
}

async fn cleanup(connection: &mut MultiplexedConnection, key: &str) {
    let _: i64 = redis::cmd("DEL").arg(key).query_async(connection).await.unwrap();
}

#[tokio::test]
async fn independent_connection_deny_blocks_late_active() {
    let (a, b, mut control) = connections(60).await;
    let t = now(&mut control).await;
    let m = session(t);
    let key = a.cache_key(&m.sid);
    // 模拟先取得数据库快照，再由另一个连接撤销，最后迟到回填。
    let deadline = a.capture_deadline(t).unwrap();
    b.revoking(&m, t / 1000, "logout").await.unwrap();
    assert_eq!(a.fill_active(&m, deadline, t, || t).await, Err(CacheError::Inactive));
    assert_eq!(a.read(&m.sid, t).await.unwrap(), CacheRead::Denied);
    let remaining = ttl(&mut control, &key).await;
    assert!(remaining > 0 && remaining <= 60_000);
    // 即便墓碑 schema 损坏也不能走普通 miss 回源分支。
    let _: i64 = redis::cmd("HSET").arg(&key).arg("CacheSchema").arg(99)
        .query_async(&mut control).await.unwrap();
    assert_eq!(a.read(&m.sid, t).await.unwrap(), CacheRead::Denied);
    b.revoked(&m, t / 1000).await.unwrap();
    assert_eq!(a.fill_active(&m, deadline, t, || t).await, Err(CacheError::Inactive));
    // 删除仅限本测试随机 SID，用于模拟墓碑已经自然消失后的旧快照。
    cleanup(&mut control, &key).await;
    assert_eq!(a.fill_active(&m, deadline, t + 60_000, || t + 60_000).await,
        Ok(FillOutcome::Stale));
    assert_eq!(a.read(&m.sid, t).await.unwrap(), CacheRead::Miss);
}

#[tokio::test]
async fn naturally_expired_deny_does_not_restart_old_active_window() {
    let (a, b, mut control) = connections(1).await;
    let t = now(&mut control).await;
    let m = session(t);
    let deadline = a.capture_deadline(t).unwrap();
    b.revoking(&m, t / 1000, "logout").await.unwrap();
    assert_eq!(a.read(&m.sid, t).await.unwrap(), CacheRead::Denied);
    // 真实等待 Redis 墓碑自然到期，不用删除或内存时钟替代 TTL 验证。
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let completed = now(&mut control).await;
    assert_eq!(ttl(&mut control, &a.cache_key(&m.sid)).await, -2);
    assert_eq!(a.fill_active(&m, deadline, completed, || completed).await,
        Ok(FillOutcome::Stale));
    assert_eq!(b.read(&m.sid, completed).await.unwrap(), CacheRead::Miss);
}

#[tokio::test]
async fn versions_schema_projection_and_deadlines() {
    let (a, b, mut control) = connections(60).await;
    let t = now(&mut control).await;
    let mut m = session(t);
    // 超过 Lua 浮点精确整数范围，仍必须保护相邻 i64 版本。
    m.version = 9_007_199_254_740_993;
    let key = a.cache_key(&m.sid);
    assert!(key.starts_with("auth:session:"));
    assert_eq!(key.len(), "auth:session:".len() + 64);
    let deadline = a.capture_deadline(t - 50_000).unwrap();
    assert_eq!(a.fill_active(&m, deadline, t, || t).await, Ok(FillOutcome::Stored));
    let remaining = ttl(&mut control, &key).await;
    assert!(remaining > 0 && remaining <= 10_000, "迟到回填不得重启六十秒窗口");
    assert_eq!(b.read(&m.sid, t).await.unwrap(), CacheRead::Active(m.clone()));
    let mut old = m.clone();
    old.version -= 1;
    assert_eq!(b.fill_active(&old, deadline, t, || t).await, Err(CacheError::Inactive));
    assert_eq!(b.revoking(&old, t / 1000, "旧版本").await, Err(SessionError::Fence));
    assert_eq!(b.read(&m.sid, t).await.unwrap(), CacheRead::Active(m.clone()));
    let fields: HashMap<String, String> = redis::cmd("HGETALL").arg(&key)
        .query_async(&mut control).await.unwrap();
    let mut actual: Vec<&str> = fields.keys().map(String::as_str).collect();
    actual.sort_unstable();
    let mut expected = vec!["SID", "UserID", "Version", "UserAuthVersion", "Status",
        "LoginMethod", "IP", "UserAgent", "CreatedAt", "LastActiveAt", "ExpiresAt",
        "RevokedAt", "RevokedReason", "CacheSchema"];
    expected.sort_unstable();
    assert_eq!(actual, expected);
    assert_eq!(fields["CacheSchema"], "1");
    assert!(!fields.values().any(|v| v.as_bytes() == SECRET));
    let _: i64 = redis::cmd("HSET").arg(&key).arg("CacheSchema").arg(2)
        .query_async(&mut control).await.unwrap();
    assert_eq!(a.read(&m.sid, t).await.unwrap(), CacheRead::InvalidEntry);
    // 回填时原子移除任何非白名单残留，避免历史 refresh 材料继续保留。
    let _: i64 = redis::cmd("HSET").arg(&key).arg("RefreshHash").arg("合成旧摘要")
        .query_async(&mut control).await.unwrap();
    assert_eq!(a.fill_active(&m, deadline, t, || t + 10_000).await,
        Ok(FillOutcome::Stale));
    let has_secret: bool = redis::cmd("HEXISTS").arg(&key).arg("RefreshHash")
        .query_async(&mut control).await.unwrap();
    assert!(!has_secret);
    cleanup(&mut control, &key).await;
    m.expires_at = t / 1000 + 5;
    assert_eq!(a.fill_active(&m, a.capture_deadline(t).unwrap(), t, || t).await,
        Ok(FillOutcome::Stored));
    let remaining = ttl(&mut control, &key).await;
    assert!(remaining > 0 && remaining <= m.expires_at * 1000 - t);
    assert_eq!(b.read(&m.sid, m.expires_at * 1000).await.unwrap(), CacheRead::Denied);
    assert_eq!(a.fill_active(&m, deadline, m.expires_at * 1000, || t).await,
        Err(CacheError::Inactive));
    b.revoking(&m, m.expires_at, "到期").await.unwrap();
    let remaining = ttl(&mut control, &key).await;
    assert!(remaining > 0 && remaining <= 1000, "非正剩余期限使用一秒墓碑");
    cleanup(&mut control, &key).await;
}

#[tokio::test]
async fn real_redis_write_and_connection_failures_are_reported() {
    let (a, _, mut control) = connections(60).await;
    let t = now(&mut control).await;
    let m = session(t);
    let key = a.cache_key(&m.sid);
    // 真实 Redis WRONGTYPE，不能被误报为已发布 fence。
    let _: () = redis::cmd("SET").arg(&key).arg("合成错误类型").arg("PX").arg(60_000)
        .query_async(&mut control).await.unwrap();
    assert_eq!(a.read(&m.sid, t).await, Err(CacheError::Protocol));
    assert_eq!(a.revoking(&m, t / 1000, "logout").await, Err(SessionError::Fence));
    assert_eq!(a.revoked(&m, t / 1000).await, Err(SessionError::Fence));
    cleanup(&mut control, &key).await;

    // 只断开本测试专用连接；需要测试 Redis 允许 CLIENT ID/KILL。
    let url = std::env::var("TEST_REDIS_URL").unwrap();
    let mut victim = redis::Client::open(url).unwrap()
        .get_multiplexed_async_connection().await.unwrap();
    let id: i64 = redis::cmd("CLIENT").arg("ID").query_async(&mut victim).await.unwrap();
    let broken = RedisSessionCache::from_connection(victim, SECRET, 60).unwrap();
    let killed: i64 = redis::cmd("CLIENT").arg("KILL").arg("ID").arg(id)
        .query_async(&mut control).await.unwrap();
    assert_eq!(killed, 1);
    assert_eq!(broken.read(&m.sid, t).await, Err(CacheError::Unavailable));
    assert_eq!(broken.revoking(&m, t / 1000, "logout").await, Err(SessionError::Fence));
    assert_eq!(broken.revoked(&m, t / 1000).await, Err(SessionError::Fence));
}
