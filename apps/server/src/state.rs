use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use newapi_catalog::PublicConfig;
use newapi_storage::Database;
use tokio::sync::watch;

#[derive(Clone)]
pub struct AppState {
    snapshot: Arc<RwLock<PublicConfig>>,
    ready: Arc<AtomicBool>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            snapshot: Arc::new(RwLock::new(PublicConfig::default())),
            ready: Arc::new(AtomicBool::new(false)),
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
        match PublicConfig::load(db, &previous).await {
            Ok(next) => {
                *self
                    .snapshot
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = next;
                self.ready.store(true, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                self.mark_not_ready();
                Err(error)
            }
        }
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
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            result = state.reload(&db) => {
                if let Err(error) = result {
                    tracing::warn!(
                        category = crate::database_error_class(&error),
                        "public configuration reload failed"
                    );
                }
            }
        }
    }
    state.mark_not_ready();
}
