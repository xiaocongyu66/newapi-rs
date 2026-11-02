use std::{net::Ipv4Addr, process::ExitCode};

use newapi_config::Config;
use newapi_server::{AppState, database_error_class, install_safe_panic_hook, reload_loop, router};
use newapi_storage::Database;
use tokio::{net::TcpListener, sync::watch};

#[tokio::main]
async fn main() -> ExitCode {
    // Fixed application-only filter: arbitrary SQLx/HTTP dependency diagnostics
    // can contain SQL, credentials or URIs. RUST_LOG is deliberately not used.
    tracing_subscriber::fmt()
        .json()
        .with_env_filter("off,newapi_server=info")
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
    let state = match AppState::initialize(&db).await {
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
    let result = axum::serve(listener, router(state.clone()))
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
