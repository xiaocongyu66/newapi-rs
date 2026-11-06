use std::{net::Ipv4Addr, process::ExitCode, sync::Arc};

use newapi_config::Config;
use newapi_identity::auth_session::{AuthFence, SessionAuth};
use newapi_identity::crypto::{AuthKeys, generate_session_secret};
use newapi_identity::session_cache::RedisSessionCache;
use newapi_identity::sessions::NoCache;
use newapi_server::{AppState, database_error_class, install_safe_panic_hook, reload_loop, router};
use newapi_storage::Database;
use tokio::{net::TcpListener, sync::watch};

#[tokio::main]
async fn main() -> ExitCode {
    // Fixed application-only filter: arbitrary SQLx/HTTP dependency diagnostics
    // can contain SQL, credentials or URIs. RUST_LOG is deliberately not used.
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("off,newapi_server=info,newapi_identity::auth_session=error")
        .with_target(false)
        .init();
    install_safe_panic_hook();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => ExitCode::FAILURE,
    }
}

async fn run() -> Result<(), ()> {
    let config = Config::from_env().map_err(|error| {
        tracing::error!(configuration_error = %error, "configuration rejected");
    })?;
    let db = Database::connect(config.dsn()).await.map_err(|error| {
        tracing::error!(
            category = database_error_class(&error),
            "database connection failed"
        );
    })?;
    let initial = match AppState::initialize(&db).await {
        Ok(state) => state,
        Err(error) => {
            tracing::error!(
                category = database_error_class(&error),
                "initial configuration load failed"
            );
            db.close().await;
            return Err(());
        }
    };
    // 未配置密钥时仅当前进程有效；重启或多实例将无法互认，必须显式告警。
    let secret = match config.session_secret() {
        Some(secret) => secret.to_owned(),
        None => match generate_session_secret() {
            Ok(secret) => {
                tracing::warn!(
                    event = "ephemeral_session_secret",
                    "SESSION_SECRET is not set; sessions will not survive restarts"
                );
                secret
            }
            Err(_) => {
                tracing::error!("session secret generation failed");
                db.close().await;
                return Err(());
            }
        },
    };
    let fence = match config.redis_url() {
        Some(url) => match RedisSessionCache::connect(
            url,
            secret.as_bytes(),
            config.sync_frequency.as_secs() as i64,
        )
        .await
        {
            Ok(cache) => AuthFence::Redis(Box::new(cache)),
            Err(_) => {
                tracing::error!(
                    event = "session_cache_unavailable",
                    "redis connection failed"
                );
                db.close().await;
                return Err(());
            }
        },
        None => AuthFence::Disabled(NoCache::explicitly_disabled()),
    };
    // 可信代理配置非法时必须终止启动，与 Go 一致；空值使用默认内网列表。
    let proxy_policy = match newapi_security::client_ip::ProxyPolicy::parse_trusted_proxies(
        config.trusted_proxies.as_deref(),
    ) {
        Ok(policy) => policy,
        Err(_) => {
            tracing::error!(
                variable = "TRUSTED_PROXIES",
                "invalid trusted proxy configuration"
            );
            db.close().await;
            return Err(());
        }
    };
    // 与 Go 一致：配置 Redis 时关键路径限流走 Redis 固定窗口；连接失败终止启动。
    let rate_limit_settings = newapi_server::limit::RateLimitSettings {
        enabled: config.critical_rate_limit_enabled,
        requests: config.critical_rate_limit_requests,
        window_seconds: config.critical_rate_limit_duration_seconds,
    };
    let rate_limiter = match config.redis_url() {
        Some(url) => match newapi_server::limit_redis::RedisRateLimiter::connect(url).await {
            Ok(limiter) => newapi_server::RateLimiter::redis(rate_limit_settings, limiter),
            Err(_) => {
                tracing::error!(
                    event = "rate_limit_redis_unavailable",
                    "redis rate limit connection failed"
                );
                db.close().await;
                return Err(());
            }
        },
        None => newapi_server::RateLimiter::memory(rate_limit_settings),
    };
    // Go `GlobalAPIRateLimit` 与关键路径共用后端选择：Redis 优先，否则进程内。
    let global_rate_limit_settings = newapi_server::limit::RateLimitSettings {
        enabled: config.global_api_rate_limit_enabled,
        requests: config.global_api_rate_limit_requests,
        window_seconds: config.global_api_rate_limit_duration_seconds,
    };
    let global_rate_limiter = match config.redis_url() {
        Some(url) => match newapi_server::limit_redis::RedisRateLimiter::connect(url).await {
            Ok(limiter) => newapi_server::RateLimiter::redis(global_rate_limit_settings, limiter),
            Err(_) => {
                tracing::error!(
                    event = "rate_limit_redis_unavailable",
                    mark = "GA",
                    "redis rate limit connection failed"
                );
                db.close().await;
                return Err(());
            }
        },
        None => newapi_server::RateLimiter::memory(global_rate_limit_settings),
    };
    let auth = SessionAuth::with_fence(db.clone(), AuthKeys::new(&secret), fence);
    let state = initial
        .bind_auth(Arc::new(auth), config.session_cookie.clone())
        .bind_runtime(db.clone(), &secret)
        .bind_transport(
            proxy_policy,
            rate_limiter,
            config.anonymous_request_body_limit_kb,
        )
        .bind_global_api_rate_limit(global_rate_limiter);
    let listener = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, config.port)).await {
        Ok(listener) => listener,
        Err(_) => {
            tracing::error!("listener initialization failed");
            state.mark_not_ready();
            db.close().await;
            return Err(());
        }
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let reload = tokio::spawn(reload_loop(
        state.clone(),
        db.clone(),
        config.sync_frequency,
        shutdown_rx,
    ));
    let signal_tx = shutdown_tx.clone();
    let signal_state = state.clone();
    tracing::info!(port = config.port, "server listening");
    // ConnectInfo 提供 peer 地址；可信代理链据此决定真实客户端 IP。
    let result = axum::serve(
        listener,
        router(state.clone()).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        signal_state.mark_not_ready();
        let _ = signal_tx.send(true);
    })
    .await;
    // 即使服务异常返回，也先通知并等待同步任务退出，再关闭连接池。
    let _ = shutdown_tx.send(true);
    let worker_failed = reload.await.is_err();
    if worker_failed {
        tracing::error!("configuration worker stopped unexpectedly");
    }
    state.mark_not_ready();
    db.close().await;
    // 不记录 JoinError 的 Debug 内容，避免将 panic 载荷写入日志。
    if worker_failed {
        return Err(());
    }
    result.map_err(|_| {
        tracing::error!("HTTP server stopped unexpectedly");
    })
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => {
                    tracing::error!("shutdown signal initialization failed");
                    return;
                }
            };
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if result.is_err() {
                    tracing::error!("interrupt signal failed");
                }
            }
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    if tokio::signal::ctrl_c().await.is_err() {
        tracing::error!("interrupt signal failed");
    }
}
