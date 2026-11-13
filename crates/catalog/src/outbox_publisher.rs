//! 网关 outbox 的 Redis 发布器与轮询循环；Go
//! `apps/api/internal/catalog/publish_gateway_config.go` 的基建半边（存储
//! 半边已在 [`crate::gateway_revision`]）。
//!
//! 契约要点（与 Go 一致）：
//! - channel：`new-api:gateway:routing-revision:v1`；载荷
//!   `{"routing_revision": <int64>}`（Go `RoutingRevisionNotice`）。
//! - `revision <= 0` → invalid（Go `fmt.Errorf("invalid routing revision %d")`）。
//! - Redis 未配置 → `ErrGatewayOutboxRedisDisabled`；发布命令失败 →
//!   `ErrGatewayOutboxRedisUnavailable` 包装。
//! - 轮询循环：间隔 `GATEWAY_OUTBOX_PUBLISH_INTERVAL_SECONDS`（缺省 1 秒，
//!   非正值回退 1 秒），每轮 `PublishPendingGatewayRevisions(ctx, 100)`；
//!   循环体**先发布再等待**，shutdown 后立即退出。
//! - 失败分类进 outbox 尝试计数：`redis_disabled` / `redis_unavailable` /
//!   `publish_error`；成功先记 `published` 再盖 `published_at`（幂等，绝不
//!   覆写首次时间戳）。
//!
//! Redis 面走 [`RoutingRevisionPublisher`] trait 端口：生产用
//! [`RedisRoutingRevisionPublisher`]（redis 0.32 multiplexed PUBLISH），
//! 测试注入替身——与 identity crate 的 token cache 同一 Redis 版本约定。

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use redis::aio::MultiplexedConnection;

use newapi_storage::Database;

use crate::gateway_revision::{
    list_pending_gateway_config_outbox, mark_gateway_config_outbox_published,
    record_gateway_config_outbox_attempt,
};

/// Go `GatewayRoutingRevisionChannel`（`publish_gateway_config.go:12`）。
pub const GATEWAY_ROUTING_REVISION_CHANNEL: &str = "new-api:gateway:routing-revision:v1";

/// Go `RunGatewayConfigOutboxPublisher` 的每轮批量上限。
pub const PUBLISH_BATCH_LIMIT: i64 = 100;

/// Go `GATEWAY_OUTBOX_PUBLISH_INTERVAL_SECONDS` 缺省值（秒）。
pub const DEFAULT_PUBLISH_INTERVAL_SECONDS: i64 = 1;

/// 发布失败分类（Go `classifyGatewayOutboxError` 的输入面）。
#[derive(Debug)]
pub enum RevisionPublishFailure {
    /// Go `ErrGatewayOutboxRedisDisabled`：Redis 未启用/未配置。
    Disabled,
    /// Go `ErrGatewayOutboxRedisUnavailable`：连接/命令失败。
    Unavailable,
}

/// Go `PublishGatewayRoutingRevision` 的错误面。
#[derive(Debug)]
pub enum OutboxPublishError {
    /// Go `invalid routing revision %d`。
    InvalidRevision(i64),
    Disabled,
    Unavailable,
    Storage(sqlx::Error),
}

impl From<sqlx::Error> for OutboxPublishError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error)
    }
}

impl std::fmt::Display for OutboxPublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRevision(revision) => {
                write!(f, "invalid routing revision {revision}")
            }
            Self::Disabled => f.write_str("gateway outbox redis disabled"),
            Self::Unavailable => f.write_str("gateway outbox redis unavailable"),
            Self::Storage(error) => write!(f, "outbox storage error: {error}"),
        }
    }
}

impl std::error::Error for OutboxPublishError {}

/// Go `classifyGatewayOutboxError`：把发布失败折算成 outbox 的有界错误类别。
pub fn classify_publish_failure(failure: &OutboxPublishError) -> &'static str {
    match failure {
        OutboxPublishError::Disabled => "redis_disabled",
        OutboxPublishError::Unavailable => "redis_unavailable",
        OutboxPublishError::InvalidRevision(_) | OutboxPublishError::Storage(_) => "publish_error",
    }
}

/// Redis 发布端口：`PUBLISH <channel> <payload>` 的异步替身点。返回
/// `Pin<Box<dyn Future>>` 以免引入 async-trait 依赖（与 server crate 的
/// transport trait 同形）。
pub trait RoutingRevisionPublisher: Send + Sync {
    fn publish(
        &self,
        channel: &str,
        payload: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevisionPublishFailure>> + Send + '_>>;
}

/// 生产实现：redis 0.32 多路复用连接上的 `PUBLISH`。连接失败折叠为
/// [`RevisionPublishFailure::Unavailable`]。
pub struct RedisRoutingRevisionPublisher {
    connection: MultiplexedConnection,
}

impl RedisRoutingRevisionPublisher {
    /// 建立连接（含握手）。调用方保证 Redis 已配置；未配置时不应构造本类型。
    pub async fn connect(url: &str) -> Result<Arc<Self>, RevisionPublishFailure> {
        let client = redis::Client::open(url).map_err(|_| RevisionPublishFailure::Disabled)?;
        let connection = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| RevisionPublishFailure::Unavailable)?;
        Ok(Arc::new(Self { connection }))
    }
}

impl RoutingRevisionPublisher for RedisRoutingRevisionPublisher {
    fn publish(
        &self,
        channel: &str,
        payload: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), RevisionPublishFailure>> + Send + '_>> {
        let mut connection = self.connection.clone();
        let channel = channel.to_owned();
        let payload = payload.to_owned();
        Box::pin(async move {
            redis::cmd("PUBLISH")
                .arg(channel)
                .arg(payload)
                .query_async::<i64>(&mut connection)
                .await
                .map(|_| ())
                .map_err(|_| RevisionPublishFailure::Unavailable)
        })
    }
}

/// Go `PublishGatewayRoutingRevision`：载荷序列化 + 发布。`revision <= 0`
/// 直接 invalid，不触达 publisher。
pub fn publish_gateway_routing_revision(
    publisher: &dyn RoutingRevisionPublisher,
    revision: i64,
) -> Pin<Box<dyn Future<Output = Result<(), OutboxPublishError>> + Send + '_>> {
    let failure = if revision <= 0 {
        Some(OutboxPublishError::InvalidRevision(revision))
    } else {
        None
    };
    let payload = serde_json::json!({ "routing_revision": revision }).to_string();
    Box::pin(async move {
        if let Some(error) = failure {
            return Err(error);
        }
        publisher
            .publish(GATEWAY_ROUTING_REVISION_CHANNEL, &payload)
            .await
            .map_err(|failure| match failure {
                RevisionPublishFailure::Disabled => OutboxPublishError::Disabled,
                RevisionPublishFailure::Unavailable => OutboxPublishError::Unavailable,
            })
    })
}

/// Go `PublishPendingGatewayRevisions`：最旧未发布批次逐条发布；单条失败
/// 记尝试分类后继续（Go `:46-51`），单条成功先记 `published` 再盖时间戳
/// （Go `:52-57`）。任一存储写失败立即上抛。
pub async fn publish_pending_gateway_revisions(
    db: &Database,
    publisher: &dyn RoutingRevisionPublisher,
    limit: i64,
) -> Result<(), sqlx::Error> {
    let rows = list_pending_gateway_config_outbox(db, limit).await?;
    for row in rows {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let result = publish_gateway_routing_revision(publisher, row.routing_revision).await;
        match result {
            Ok(()) => {
                record_gateway_config_outbox_attempt(db, row.id, "published").await?;
                mark_gateway_config_outbox_published(db, row.id, now).await?;
            }
            Err(error) => {
                record_gateway_config_outbox_attempt(db, row.id, classify_publish_failure(&error))
                    .await?;
            }
        }
    }
    Ok(())
}

/// Go `RunGatewayConfigOutboxPublisher`：固定间隔轮询，`shutdown` 完成即
/// 退出（Go 的 `ctx.Done()`）。每轮「先发布、再等待 ticker/退出」。间隔
/// 缺省 1 秒，非正值回退 1 秒（Go `:63-66`）。
pub async fn run_gateway_config_outbox_publisher(
    db: &Database,
    publisher: &dyn RoutingRevisionPublisher,
    interval_seconds: i64,
    shutdown: impl Future<Output = ()>,
) {
    let interval = if interval_seconds <= 0 {
        Duration::from_secs(DEFAULT_PUBLISH_INTERVAL_SECONDS as u64)
    } else {
        Duration::from_secs(interval_seconds as u64)
    };
    let mut shutdown = std::pin::pin!(shutdown);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let _ = publish_pending_gateway_revisions(db, publisher, PUBLISH_BATCH_LIMIT).await;
        tokio::select! {
            _ = &mut shutdown => return,
            _ = ticker.tick() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_matches_go_table() {
        assert_eq!(
            classify_publish_failure(&OutboxPublishError::Disabled),
            "redis_disabled"
        );
        assert_eq!(
            classify_publish_failure(&OutboxPublishError::Unavailable),
            "redis_unavailable"
        );
        assert_eq!(
            classify_publish_failure(&OutboxPublishError::InvalidRevision(0)),
            "publish_error"
        );
    }

    #[tokio::test]
    async fn invalid_revision_never_reaches_publisher() {
        // revision <= 0：直接 invalid，publisher 不会被调用（None publisher
        // 在此不可表达，故用一个恒 Disabled 的替身验证同样不触达）。
        struct Disabled;
        impl RoutingRevisionPublisher for Disabled {
            fn publish(
                &self,
                _: &str,
                _: &str,
            ) -> Pin<Box<dyn Future<Output = Result<(), RevisionPublishFailure>> + Send + '_>>
            {
                Box::pin(async { Err(RevisionPublishFailure::Disabled) })
            }
        }
        let error = publish_gateway_routing_revision(&Disabled, 0)
            .await
            .unwrap_err();
        assert!(matches!(error, OutboxPublishError::InvalidRevision(0)));
        let error = publish_gateway_routing_revision(&Disabled, -7)
            .await
            .unwrap_err();
        assert!(matches!(error, OutboxPublishError::InvalidRevision(-7)));
    }
}
