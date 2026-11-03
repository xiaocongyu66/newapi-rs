//! 真实 Redis 契约测试；TEST_REDIS_URL 缺失必须失败，不允许静默跳过。
//! 只操作随机 SID 对应的键，不清空数据库，不读取凭据文件或打印连接配置。
use std::time::Duration;

use newapi_identity::session_cache::{
    CacheError, CacheRead, FillOutcome, IO_TIMEOUT, RedisSessionCache,
};
use newapi_identity::sessions::{RevocationFence, SessionError, SessionMetadata};
use redis::aio::MultiplexedConnection;

const SECRET: &[u8] = b"synthetic-redis-contract-test-secret-not-for-production";

struct Fixture {
    writer: RedisSessionCache,
    reader: RedisSessionCache,
    control: MultiplexedConnection,
}

async fn connection(client: &redis::Client) -> MultiplexedConnection {
    tokio::time::timeout(IO_TIMEOUT, client.get_multiplexed_async_connection())
        .await
        .unwrap_or_else(|_| panic!("真实 Redis 测试连接超时"))
        .unwrap_or_else(|_| panic!("无法连接真实 Redis；请检查测试配置"))
}

async fn fixture(seconds: i64) -> Fixture {
    let url =
        std::env::var("TEST_REDIS_URL").expect("真实 Redis 测试必须设置 TEST_REDIS_URL，禁止跳过");
    let client = redis::Client::open(url)
        .unwrap_or_else(|_| panic!("TEST_REDIS_URL 必须是有效的 Redis 测试配置"));
    let writer = connection(&client).await;
    let reader = connection(&client).await;
    let control = connection(&client).await;
    Fixture {
        writer: RedisSessionCache::from_connection(writer, SECRET, seconds).unwrap(),
        reader: RedisSessionCache::from_connection(reader, SECRET, seconds).unwrap(),
        control,
    }
}

async fn now_ms(control: &mut MultiplexedConnection) -> i64 {
    let (seconds, micros): (i64, i64) =
        tokio::time::timeout(IO_TIMEOUT, redis::cmd("TIME").query_async(control))
            .await
            .expect("Redis TIME 超时")
            .unwrap_or_else(|_| panic!("Redis TIME 失败"));
    seconds * 1000 + micros / 1000
}

async fn ttl_ms(control: &mut MultiplexedConnection, key: &str) -> i64 {
    tokio::time::timeout(IO_TIMEOUT, redis::cmd("PTTL").arg(key).query_async(control))
        .await
        .expect("Redis PTTL 超时")
        .unwrap_or_else(|_| panic!("Redis PTTL 失败"))
}

async fn cleanup(control: &mut MultiplexedConnection, key: &str) {
    let _: i64 = tokio::time::timeout(IO_TIMEOUT, redis::cmd("DEL").arg(key).query_async(control))
        .await
        .expect("测试键清理超时")
        .unwrap_or_else(|_| panic!("测试键清理失败"));
}

fn session(now: i64) -> SessionMetadata {
    SessionMetadata {
        sid: format!("redis-contract-{:032x}", rand::random::<u128>()),
        user_id: 42,
        version: 1,
        user_auth_version: 3,
        status: "active".into(),
        login_method: "password".into(),
        ip: "192.0.2.1".into(),
        user_agent: "synthetic-redis-contract-test".into(),
        created_at: now / 1000,
        last_active_at: now / 1000,
        expires_at: now / 1000 + 3600,
        revoked_at: 0,
        revoked_reason: String::new(),
    }
}

#[tokio::test]
async fn redis_revoking_denies_until_expiry_without_reviving_old_snapshot() {
    let mut f = fixture(2).await;
    let t = now_ms(&mut f.control).await;
    let m = session(t);
    let key = f.writer.cache_key(&m.sid);
    let deadline = f.reader.capture_deadline(t).unwrap();
    // 显式固定业务测试时钟；Redis 自身的到期计时仍然真实运行。
    let writer = f.writer.with_clock(move || Ok(t));
    writer.revoking(&m, t / 1000, "logout").await.unwrap();
    let remaining = ttl_ms(&mut f.control, &key).await;
    assert!(remaining > 0 && remaining <= 2000);
    assert_eq!(f.reader.read(&m.sid, t).await, Ok(CacheRead::Denied));
    assert_eq!(
        f.reader.fill_active(&m, deadline, t, || t).await,
        Err(CacheError::Inactive)
    );

    // 不 DEL、不伪造 Redis 时间，等待墓碑自然到期。
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let after = now_ms(&mut f.control).await;
    assert_eq!(ttl_ms(&mut f.control, &key).await, -2);
    assert_eq!(f.reader.read(&m.sid, after).await, Ok(CacheRead::Miss));
    assert_eq!(
        f.reader.fill_active(&m, deadline, after, || after).await,
        Ok(FillOutcome::Stale)
    );
    // Miss 仅允许权威回源，不代表认证成功，也不能重启旧快照窗口。
    assert_eq!(f.reader.read(&m.sid, after).await, Ok(CacheRead::Miss));
}

#[tokio::test]
async fn redis_same_sid_guards_versions_and_keeps_deny_across_versions() {
    let mut f = fixture(60).await;
    let t = now_ms(&mut f.control).await;
    let mut older = session(t);
    // 相邻版本超过 Lua 浮点数精确范围，不能因舍入混淆。
    older.version = i64::MAX - 2;
    let mut newer = older.clone();
    newer.version += 1;
    let key = f.writer.cache_key(&older.sid);
    let deadline = f.writer.capture_deadline(t).unwrap();
    for m in [&older, &newer] {
        assert_eq!(
            f.writer.fill_active(m, deadline, t, || t).await,
            Ok(FillOutcome::Stored)
        );
        assert_eq!(
            f.reader.read(&m.sid, t).await,
            Ok(CacheRead::Active(m.clone()))
        );
    }
    assert_eq!(
        f.writer.fill_active(&older, deadline, t, || t).await,
        Err(CacheError::Inactive)
    );
    assert_eq!(
        f.writer.revoking(&older, t / 1000, "stale").await,
        Err(SessionError::Fence)
    );
    assert_eq!(
        f.writer.revoked(&older, t / 1000).await,
        Err(SessionError::Fence)
    );
    assert_eq!(
        f.reader.read(&newer.sid, t).await,
        Ok(CacheRead::Active(newer.clone()))
    );

    f.writer.revoking(&newer, t / 1000, "logout").await.unwrap();
    let mut newest = newer.clone();
    newest.version += 1;
    // SID 是键的唯一会话标识；不能把版本隔离误解为高版本绕过墓碑。
    for m in [&older, &newer, &newest] {
        assert_eq!(
            f.writer.fill_active(m, deadline, t, || t).await,
            Err(CacheError::Inactive)
        );
    }
    assert_eq!(f.reader.read(&newer.sid, t).await, Ok(CacheRead::Denied));
    cleanup(&mut f.control, &key).await;
}

#[tokio::test]
async fn redis_revoked_write_failure_is_visible_to_caller() {
    let mut f = fixture(60).await;
    let t = now_ms(&mut f.control).await;
    let mut m = session(t);
    let key = f.writer.cache_key(&m.sid);
    f.writer.revoking(&m, t / 1000, "logout").await.unwrap();
    assert_eq!(f.reader.read(&m.sid, t).await, Ok(CacheRead::Denied));
    m.status = "revoked".into();
    m.revoked_at = t / 1000;
    m.revoked_reason = "logout".into();

    // 仅破坏本测试随机键的类型，真实 Redis 的 HGET/Lua 将报告 WRONGTYPE。
    // 不使用连接建立失败冒充已经调用 revoked 的终态写入失败。
    let _: () = tokio::time::timeout(
        IO_TIMEOUT,
        redis::cmd("SET")
            .arg(&key)
            .arg("synthetic-wrong-type")
            .arg("PX")
            .arg(60_000)
            .query_async(&mut f.control),
    )
    .await
    .expect("Redis 故障注入超时")
    .unwrap_or_else(|_| panic!("Redis 故障注入失败"));
    assert_eq!(
        f.writer.revoked(&m, t / 1000).await,
        Err(SessionError::Fence)
    );
    assert_eq!(f.reader.read(&m.sid, t).await, Err(CacheError::Protocol));
    cleanup(&mut f.control, &key).await;

    // 同一份有效终态元数据在移除类型故障后可以发布，排除输入校验失败。
    f.writer.revoked(&m, t / 1000).await.unwrap();
    assert_eq!(f.reader.read(&m.sid, t).await, Ok(CacheRead::Denied));
    cleanup(&mut f.control, &key).await;
}

#[tokio::test]
async fn redis_active_and_deny_ttl_are_bounded_by_session_remaining_lifetime() {
    let mut f = fixture(60).await;
    let t = now_ms(&mut f.control).await;
    let mut m = session(t);
    m.expires_at = t / 1000 + 10;
    let remaining = m.expires_at * 1000 - t;
    let key = f.writer.cache_key(&m.sid);
    // 固定发布时钟用于验证精确上界；不依赖客户端与 Redis 系统钟一致。
    let writer = f.writer.with_clock(move || Ok(t));
    let deadline = writer.capture_deadline(t).unwrap();
    assert_eq!(
        writer.fill_active(&m, deadline, t, || t).await,
        Ok(FillOutcome::Stored)
    );
    let ttl = ttl_ms(&mut f.control, &key).await;
    assert!(ttl > 0 && ttl <= remaining && ttl < 60_000);
    assert_eq!(
        f.reader.read(&m.sid, t).await,
        Ok(CacheRead::Active(m.clone()))
    );

    writer.revoking(&m, t / 1000, "logout").await.unwrap();
    let ttl = ttl_ms(&mut f.control, &key).await;
    assert!(ttl > 0 && ttl <= remaining && ttl < 60_000);
    assert_eq!(f.reader.read(&m.sid, t).await, Ok(CacheRead::Denied));

    m.status = "revoked".into();
    m.revoked_at = t / 1000;
    m.revoked_reason = "logout".into();
    writer.revoked(&m, t / 1000).await.unwrap();
    let ttl = ttl_ms(&mut f.control, &key).await;
    assert!(ttl > 0 && ttl <= remaining && ttl < 60_000);
    assert_eq!(f.reader.read(&m.sid, t).await, Ok(CacheRead::Denied));
    cleanup(&mut f.control, &key).await;
}
