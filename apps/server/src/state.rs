use std::net::IpAddr;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use newapi_billing::quota_display::QuotaDisplay;
use newapi_catalog::{AuthSettings, PublicConfig};
use newapi_config::SessionCookieSettings;
use newapi_identity::auth_flow::auth_flow_key;
use newapi_identity::auth_session::{AuthFence, SessionAuth};
use newapi_identity::self_user::{QuotaDisplayKind, QuotaDisplaySettings};
use newapi_security::client_ip::{ProxyPolicy, resolve_client_ip};
use newapi_storage::Database;
use tokio::sync::watch;

use crate::boundary_mw::anonymous_body_limit_bytes;
use crate::limit::{RateLimitSettings, SlidingWindowLimiter};
use crate::limit_redis::{RateLimitVerdict, RedisRateLimiter};

/// Go `CriticalRateLimit` 的后端选择：配置 Redis 时走固定窗口，否则进程内滑动窗口。
enum RateLimiterBackend {
    Memory(SlidingWindowLimiter),
    Redis(RedisRateLimiter),
}

/// Redis 限流后端故障；Go 对应 500 + Abort，不向客户端转述底层错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitUnavailable;

/// 关键路径限流的完整状态（开关、阈值与后端），生产启动时由 `main` 构建。
pub struct RateLimiter {
    settings: RateLimitSettings,
    backend: RateLimiterBackend,
}

impl RateLimiter {
    pub fn memory(settings: RateLimitSettings) -> Self {
        Self {
            settings,
            backend: RateLimiterBackend::Memory(SlidingWindowLimiter::new(settings)),
        }
    }

    pub fn redis(settings: RateLimitSettings, limiter: RedisRateLimiter) -> Self {
        Self {
            settings,
            backend: RateLimiterBackend::Redis(limiter),
        }
    }

    async fn check(
        &self,
        mark: &str,
        client_ip: &str,
        now: i64,
    ) -> Result<Option<i64>, RateLimitUnavailable> {
        if !self.settings.enabled {
            return Ok(None);
        }
        match &self.backend {
            RateLimiterBackend::Memory(limiter) => {
                let (allowed, retry_after) = limiter.check(&format!("{mark}{client_ip}"), now);
                Ok((!allowed).then_some(retry_after))
            }
            RateLimiterBackend::Redis(limiter) => match limiter
                .check(
                    mark,
                    client_ip,
                    self.settings.requests,
                    self.settings.window_seconds,
                )
                .await
            {
                Ok(RateLimitVerdict::Allowed) => Ok(None),
                Ok(RateLimitVerdict::Rejected { retry_after }) => Ok(Some(retry_after)),
                Err(_) => {
                    tracing::error!(
                        event = "rate_limit_redis_error",
                        "redis rate limit check failed"
                    );
                    Err(RateLimitUnavailable)
                }
            },
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    snapshot: Arc<RwLock<PublicConfig>>,
    ready: Arc<AtomicBool>,
    auth: Option<Arc<SessionAuth<AuthFence>>>,
    session_cookie: Arc<SessionCookieSettings>,
    db: Option<Database>,
    auth_settings: Arc<RwLock<AuthSettings>>,
    quota_display: Arc<RwLock<QuotaDisplay>>,
    /// auth_flow 的 HMAC key：`auth-flow-v1:` + session secret，与 Go 一致。
    flow_key: Option<Arc<Vec<u8>>>,
    /// 可信代理解析策略；未注入时只信任直连 peer（测试路径）。
    proxy_policy: Option<Arc<ProxyPolicy>>,
    /// `CriticalRateLimit`；未注入时不做限流（测试路径）。
    rate_limiter: Option<Arc<RateLimiter>>,
    anonymous_body_limit: usize,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(PublicConfig::default())),
            ready: Arc::new(AtomicBool::new(false)),
            auth: None,
            session_cookie: Arc::new(SessionCookieSettings {
                secure: false,
                trusted_origins: Vec::new(),
            }),
            db: None,
            auth_settings: Arc::new(RwLock::new(AuthSettings::default())),
            quota_display: Arc::new(RwLock::new(QuotaDisplay::default())),
            flow_key: None,
            proxy_policy: None,
            rate_limiter: None,
            anonymous_body_limit: anonymous_body_limit_bytes(512),
        }
    }
}

impl AppState {
    /// No listener should be opened until this has succeeded.
    pub async fn initialize(db: &Database) -> Result<Self, sqlx::Error> {
        let state = Self::default();
        state.reload(db).await?;
        Ok(state)
    }

    pub fn snapshot(&self) -> PublicConfig {
        self.snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// 在开放监听前注入认证编排；未注入时会话端点统一返回不可用。
    pub fn bind_auth(
        mut self,
        auth: Arc<SessionAuth<AuthFence>>,
        cookie: SessionCookieSettings,
    ) -> Self {
        self.auth = Some(auth);
        self.session_cookie = Arc::new(cookie);
        self
    }

    /// 注入登录编排所需的连接池与 flow key；session secret 与 Go 的
    /// `auth-flow-v1:` 前缀派生保持一致。
    pub fn bind_runtime(mut self, db: Database, session_secret: &str) -> Self {
        self.flow_key = Some(Arc::new(auth_flow_key(session_secret)));
        self.db = Some(db);
        self
    }

    /// 注入传输层安全设置：可信代理、关键路径限流与匿名请求体上限。
    /// 生产入口必须调用；测试与 P1 端点保持无代理、无限流的默认。
    pub fn bind_transport(
        mut self,
        proxy_policy: ProxyPolicy,
        rate_limit: RateLimiter,
        anonymous_request_body_limit_kb: i64,
    ) -> Self {
        self.proxy_policy = Some(Arc::new(proxy_policy));
        self.rate_limiter = Some(Arc::new(rate_limit));
        self.anonymous_body_limit = anonymous_body_limit_bytes(anonymous_request_body_limit_kb);
        self
    }

    /// 解析客户端 IP：peer 不可信时忽略转发头，与 Go `resolveTrustedClientIP` 一致。
    pub fn client_ip(
        &self,
        peer: Option<IpAddr>,
        forwarded_for: Option<&str>,
        real_ip: Option<&str>,
    ) -> String {
        match &self.proxy_policy {
            Some(policy) => resolve_client_ip(peer, forwarded_for, real_ip, policy),
            None => peer.map(|ip| ip.to_string()).unwrap_or_default(),
        }
    }

    /// 关键路径限流：`Ok(Some(retry_after))` 拒绝，`Ok(None)` 放行；
    /// `Err(RateLimitUnavailable)` 表示 Redis 后端故障（Go 回复 500）。
    pub async fn check_rate_limit(
        &self,
        mark: &str,
        client_ip: &str,
        now: i64,
    ) -> Result<Option<i64>, RateLimitUnavailable> {
        match self.rate_limiter.as_ref() {
            Some(limiter) => limiter.check(mark, client_ip, now).await,
            None => Ok(None),
        }
    }

    /// 匿名请求体上限（字节）；0 表示 Go 语义下的“未启用”。
    pub fn anonymous_body_limit(&self) -> usize {
        self.anonymous_body_limit
    }

    pub fn auth(&self) -> Option<&SessionAuth<AuthFence>> {
        self.auth.as_deref()
    }

    pub fn auth_arc(&self) -> Option<Arc<SessionAuth<AuthFence>>> {
        self.auth.clone()
    }

    pub fn db(&self) -> Option<Database> {
        self.db.clone()
    }

    pub fn flow_key(&self) -> Option<&[u8]> {
        self.flow_key.as_deref().map(Vec::as_slice)
    }

    pub fn auth_settings(&self) -> AuthSettings {
        self.auth_settings
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// SelfUser 组装用的额度展示设置（billing 快照 → identity 算术设置）。
    pub fn quota_display(&self) -> QuotaDisplaySettings {
        let display = *self
            .quota_display
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let kind = match display.display_type {
            newapi_billing::quota_display::QuotaDisplayType::Cny => QuotaDisplayKind::Cny {
                usd_exchange_rate: display.usd_exchange_rate,
            },
            newapi_billing::quota_display::QuotaDisplayType::Custom => QuotaDisplayKind::Custom {
                rate: display.custom_rate,
            },
            newapi_billing::quota_display::QuotaDisplayType::Tokens => QuotaDisplayKind::Tokens,
            newapi_billing::quota_display::QuotaDisplayType::Usd => QuotaDisplayKind::Usd,
        };
        QuotaDisplaySettings {
            quota_per_unit: display.quota_per_unit,
            kind,
        }
    }

    pub fn session_cookie(&self) -> &SessionCookieSettings {
        &self.session_cookie
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub fn mark_not_ready(&self) {
        self.ready.store(false, Ordering::Release);
    }

    /// Called by a single reload worker. Never hold the std lock across await.
    /// A failed read cannot partially publish a configuration.
    pub async fn reload(&self, db: &Database) -> Result<(), sqlx::Error> {
        let previous = self.snapshot();
        let next = match PublicConfig::load(db, &previous).await {
            Ok(next) => next,
            Err(error) => {
                self.mark_not_ready();
                return Err(error);
            }
        };
        // 认证与额度展示快照与公共配置同频刷新；失败同样不发布部分状态。
        let auth_previous = self.auth_settings();
        let auth_next = match AuthSettings::load(db, &auth_previous).await {
            Ok(next) => next,
            Err(error) => {
                self.mark_not_ready();
                return Err(error);
            }
        };
        let quota_previous = *self
            .quota_display
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let quota_next = match QuotaDisplay::load(db, &quota_previous).await {
            Ok(next) => next,
            Err(error) => {
                self.mark_not_ready();
                return Err(error);
            }
        };
        *self
            .quota_display
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = quota_next;
        *self
            .auth_settings
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = auth_next;
        *self
            .snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
        self.ready.store(true, Ordering::Release);
        Ok(())
    }
}

/// The first refresh is delayed, matching the original sleep-before-sync loop.
/// Dropping the sender also stops the worker. In-flight reads are cancelled on
/// shutdown; shutdown never waits for a database timeout before closing pools.
pub async fn reload_loop(
    state: AppState,
    db: Database,
    frequency: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(frequency) => {}
        }
        if !reload_until_shutdown(&state, &db, &mut shutdown).await {
            break;
        }
    }
    state.mark_not_ready();
}

// 返回 false 表示退出；直接丢弃未完成的数据库读取，不等待连接池超时。
async fn reload_until_shutdown(
    state: &AppState,
    db: &Database,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        biased;
        _ = shutdown.changed() => {
            state.mark_not_ready();
            false
        }
        result = state.reload(db) => {
            if let Err(error) = result {
                tracing::warn!(
                    category = crate::database_error_class(&error),
                    "public configuration reload failed"
                );
            }
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, task::Poll};

    #[tokio::test]
    async fn shutdown_cancels_in_flight_reload_waiting_for_pool() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(60))
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(r#"INSERT INTO options VALUES ('Notice', 'last good value')"#)
            .execute(&pool)
            .await
            .unwrap();
        let db = Database::Sqlite(pool.clone());
        let state = AppState::initialize(&db).await.unwrap();
        // 独占唯一连接，使真实 catalog 读取确定阻塞在连接获取阶段。
        let held = pool.acquire().await.unwrap();
        assert_eq!(pool.num_idle(), 0);
        for drop_sender in [false, true] {
            state.ready.store(true, Ordering::Release);
            let (tx, mut rx) = watch::channel(false);
            let mut reload = Box::pin(reload_until_shutdown(&state, &db, &mut rx));
            // 手工 poll 确认读取已进入 Pending，再触发退出；不依赖 sleep 猜时序。
            std::future::poll_fn(|cx| {
                assert!(reload.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert!(state.is_ready());
            if !drop_sender {
                tx.send(true).unwrap();
            }
            drop(tx);
            let completed = tokio::time::timeout(Duration::from_secs(2), reload)
                .await
                .expect("shutdown must not wait for pool acquisition timeout");
            assert!(!completed);
            assert!(!state.is_ready());
            assert_eq!(state.snapshot().notice, "last good value");
            assert_eq!(pool.num_idle(), 0);
        }
        // 退出发生时测试仍持有连接，证明不是连接释放后读取自然完成。
        drop(held);
        tokio::time::timeout(Duration::from_secs(2), db.close())
            .await
            .unwrap();
    }
}
