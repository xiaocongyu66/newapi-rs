//! 仅运行于显式配置的真实 Redis；环境缺失必须失败，不允许忽略或内存替代。
//! 集成者需先导出 sessions 与 session_cache 模块，并补齐精确依赖。
use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicI64, Ordering}};
use std::time::{Duration, Instant};

use newapi_identity::session_cache::IO_TIMEOUT;
use tokio::net::{TcpListener, TcpStream};

use newapi_identity::session_cache::{CacheError, CacheRead, FillOutcome, RedisSessionCache};
use newapi_identity::sessions::{RevocationFence, SessionError, SessionMetadata};
use redis::aio::MultiplexedConnection;

const SECRET: &[u8] = b"synthetic-session-cache-secret-not-for-production";

#[tokio::test]
async fn session_key_matches_fixed_go_oracle() {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Vector {
        secret: String,
        sid: String,
        key: String,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Oracle {
        schema: u32,
        vectors: Vec<Vector>,
    }
    // 缺失或损坏的远程 Go 样本必须失败，不能退回本地算法生成期望。
    let path = std::env::var("P2_SESSION_KEY_ORACLE_PATH")
        .expect("必须设置远程 Go 生成的 P2_SESSION_KEY_ORACLE_PATH");
    let bytes = std::fs::read(path).expect("必须能读取 Go 会话 key 金标准");
    let oracle: Oracle = serde_json::from_slice(&bytes).expect("Go 会话 key 样本格式必须有效");
    assert_eq!(oracle.schema, 1);
    let secrets = ["test-session-secret-with-sufficient-entropy", "public-session-cache-secret-密码"];
    let sids = ["session-1", "123e4567-e89b-42d3-a456-426614174000", "session-密码\0tail"];
    assert_eq!(oracle.vectors.len(), secrets.len() * sids.len());
    let (_, _, connection) = connections(60).await;
    for (index, vector) in oracle.vectors.iter().enumerate() {
        // 固定输入及顺序，防止空数组、删减样本或替换测试输入形成假通过。
        assert_eq!(vector.secret, secrets[index / sids.len()]);
        assert_eq!(vector.sid, sids[index % sids.len()]);
        let cache = RedisSessionCache::from_connection(
            connection.clone(), vector.secret.as_bytes(), 60,
        ).unwrap();
        assert_eq!(cache.cache_key(&vector.sid), vector.key);
    }
}

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
    m.version = i64::MAX;
    let key = a.cache_key(&m.sid);
    assert!(key.starts_with("auth:session:"));
    assert_eq!(key.len(), "auth:session:".len() + 64);
    assert!(matches!(a.capture_deadline(i64::MAX), Err(CacheError::Invalid)));
    let mut overflow = m.clone();
    overflow.expires_at = i64::MAX;
    assert_eq!(a.fill_active(&overflow, a.capture_deadline(t).unwrap(), t, || t).await,
        Err(CacheError::Invalid));
    assert_eq!(b.revoking(&overflow, t / 1000, "溢出输入").await, Err(SessionError::Fence));
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
    let expired_ms = m.expires_at * 1000;
    let b = b.with_clock(move || Ok(expired_ms));
    b.revoking(&m, m.expires_at, "到期").await.unwrap();
    let remaining = ttl(&mut control, &key).await;
    assert!(remaining > 0 && remaining <= 1000, "非正剩余期限使用一秒墓碑");
    cleanup(&mut control, &key).await;
}

#[tokio::test]
async fn binary_metadata_cannot_bypass_deny() {
    let (a, b, mut control) = connections(60).await;
    let t = now(&mut control).await;
    let m = session(t);
    let key = a.cache_key(&m.sid);
    for status in ["revoking", "revoked"] {
        for field in ["UserAgent", "ExtraField"] {
            b.revoking(&m, t / 1000, "logout").await.unwrap();
            let _: i64 = redis::cmd("HSET").arg(&key)
                .arg("Status").arg(status).arg(field).arg(&[0xff_u8][..])
                .query_async(&mut control).await.unwrap();
            assert_eq!(a.read(&m.sid, t).await.unwrap(), CacheRead::Denied);
            cleanup(&mut control, &key).await;
        }
    }
}

#[tokio::test]
async fn deny_ttl_uses_publication_milliseconds_not_audit_seconds() {
    let (a, b, mut control) = connections(60).await;
    let t = now(&mut control).await;
    let mut m = session(t);
    m.expires_at = t / 1000 + 10;
    let expiry_ms = m.expires_at * 1000;
    let clock = Arc::new(AtomicI64::new(expiry_ms - 1750));
    let injected = clock.clone();
    let b = b.with_clock(move || Ok(injected.load(Ordering::SeqCst)));
    let key = a.cache_key(&m.sid);
    // 审计时间保持不变，发布时钟包含毫秒且已晚于审计时间。
    b.revoking(&m, t / 1000, "延迟发布").await.unwrap();
    let remaining = ttl(&mut control, &key).await;
    assert!(remaining > 0 && remaining <= 1750);
    let audited: i64 = redis::cmd("HGET").arg(&key).arg("RevokedAt")
        .query_async(&mut control).await.unwrap();
    assert_eq!(audited, t / 1000);
    clock.store(expiry_ms - 750, Ordering::SeqCst);
    b.revoked(&m, t / 1000).await.unwrap();
    let remaining = ttl(&mut control, &key).await;
    assert!(remaining > 0 && remaining <= 750);
    clock.store(expiry_ms + 500, Ordering::SeqCst);
    b.revoking(&m, t / 1000, "已到期").await.unwrap();
    let remaining = ttl(&mut control, &key).await;
    assert!(remaining > 0 && remaining <= 1000);
    cleanup(&mut control, &key).await;
}

#[tokio::test]
async fn handshake_without_response_has_finite_timeout() {
    // 仍强制真实 Redis 环境；黑洞仅用于传输故障注入，不伪装缓存实现。
    let _real = connections(60).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let started = Instant::now();
    let result = tokio::time::timeout(IO_TIMEOUT + Duration::from_secs(2),
        RedisSessionCache::connect(&format!("redis://{address}/"), SECRET, 60)).await;
    task.abort();
    let _ = task.await;
    assert!(matches!(result, Ok(Err(CacheError::Unavailable))));
    assert!(started.elapsed() >= IO_TIMEOUT);
}

#[tokio::test]
async fn established_connection_without_command_responses_times_out() {
    let (_a, _b, mut control) = connections(60).await;
    let t = now(&mut control).await;
    let m = session(t);
    let url = std::env::var("TEST_REDIS_URL").unwrap();
    let client = redis::Client::open(url).unwrap();
    let mut info = client.get_connection_info().clone();
    // 故障代理转发真实 Redis 协议，需 CI 提供普通 TCP Redis；不模拟任何响应。
    let upstream = match &info.addr {
        redis::ConnectionAddr::Tcp(host, port) => (host.clone(), *port),
        _ => panic!("传输故障测试要求 TEST_REDIS_URL 使用普通 TCP"),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    info.addr = redis::ConnectionAddr::Tcp(address.ip().to_string(), address.port());
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let (stalled_tx, stalled_rx) = tokio::sync::oneshot::channel::<()>();
    let proxy = tokio::spawn(async move {
        let (mut downstream, _) = listener.accept().await.unwrap();
        let mut upstream = TcpStream::connect(upstream).await.unwrap();
        tokio::select! {
            result = tokio::io::copy_bidirectional(&mut downstream, &mut upstream) => {
                panic!("真实 Redis 转发意外结束：{result:?}");
            }
            _ = stop_rx => {}
        }
        stalled_tx.send(()).unwrap();
        // 保持两端连接存活，仅停止转发，区别于 CLIENT KILL。
        std::future::pending::<()>().await;
        drop((downstream, upstream));
    });
    let connection = tokio::time::timeout(Duration::from_secs(5),
        redis::Client::open(info).unwrap().get_multiplexed_async_connection())
        .await.unwrap().unwrap();
    let cache = RedisSessionCache::from_connection(connection, SECRET, 60).unwrap();
    stop_tx.send(()).unwrap();
    stalled_rx.await.unwrap();
    let results = tokio::time::timeout(IO_TIMEOUT * 4 + Duration::from_secs(2), async {
        let read = cache.read(&m.sid, t).await;
        let fill = cache.fill_active(&m, cache.capture_deadline(t).unwrap(), t, || t).await;
        let pending = cache.revoking(&m, t / 1000, "logout").await;
        let terminal = cache.revoked(&m, t / 1000).await;
        (read, fill, pending, terminal)
    }).await;
    proxy.abort();
    let _ = proxy.await;
    let (read, fill, pending, terminal) = results.expect("每个命令必须有限返回");
    assert_eq!(read, Err(CacheError::Unavailable));
    assert_eq!(fill, Err(CacheError::Unavailable));
    assert_eq!(pending, Err(SessionError::Fence));
    assert_eq!(terminal, Err(SessionError::Fence));
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
