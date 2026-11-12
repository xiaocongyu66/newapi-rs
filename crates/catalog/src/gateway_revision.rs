//! 网关路由修订号机制：`gateway_config_revisions` 单例水位 + 同事务 bump +
//! `gateway_config_outboxes` 发布暂存。
//!
//! Go 参考（`/root/newapi/apps/api/internal/catalog`）：
//! - `store_gateway_revision.go`：`GatewayConfigRevision`（全局提交水位，
//!   单例 id=1，非逐实体版本）、`GatewayConfigOutbox`（提交后发布唤醒通知，
//!   不携带任何配置载荷）、`InitializeGatewayConfigRevision`、
//!   `BumpGatewayRoutingRevision`、`MutateGatewayRouting`
//!   （单外层事务：域写入 + 修订号 bump + outbox 行同提交同回滚）。
//! - `publish_gateway_config.go` 的存储部分（outbox 待发布列表 / 尝试计数 /
//!   幂等发布标记）；Redis 发布器与轮询循环属基建域，本切片不移植。
//! - `settings/settings.go:94-105` 的 `GatewayRoutingOptionKeys`（显式白名单，
//!   这些 option 的写入必须推进修订号，见 `apps/server/src/option_store.rs`）。
//!
//! 契约要点（与 Go 一致）：
//! - 修订号是**全局提交水位**：一次路由可见变更 = 恰好一次 bump，存单例行
//!   （id=1）。bump 是原子单行 UPDATE（`routing_revision + 1`），并发变更靠
//!   行锁串行化，两个并发成功提交必然拿到不同且递增的修订号。
//! - 事务失败 → bump 同回滚 → 修订号不推进；消费方视 0 为“从未发布”，
//!   因此失败绝不退化成 0（行缺失/水位非正都是硬错误）。
//! - `routing_revision` 在 outbox 上唯一：一个修订号只发布一次。
//!
//! Rust 侧的 `MutateGatewayRouting` 等价物是 [`macro@crate::mutate_routing!`]：
//! 两个驱动各展开一份“begin → body → bump → commit/rollback”，与
//! `channels/store.rs` 原 `transactional!` 宏同构，只是 commit 前强制 bump。

use newapi_storage::Database;
use sqlx::Row;

/// Go `gatewayConfigRevisionID`（`store_gateway_revision.go:15`）：水位表
/// 全部署只此一行。
pub const GATEWAY_CONFIG_REVISION_ID: i64 = 1;

/// Go `settings.GatewayRoutingOptionKeys`（`settings.go:94-100`）：写入这些
/// option 必须包在路由修订事务里（`dbinfra.UpdateOption`/`UpdateOptionsBulk`）。
pub const GATEWAY_ROUTING_OPTION_KEYS: &[&str] = &[
    "ModelRatio",
    "ModelPrice",
    "CompletionRatio",
    "CacheRatio",
    "CreateCacheRatio",
    "ImageRatio",
    "AudioRatio",
    "AudioCompletionRatio",
    "GroupRatio",
    "GroupGroupRatio",
    "UserUsableGroups",
    "AutoGroups",
    "MaxTokenAutoGroups",
];

/// Go `IsGatewayRoutingOptionKey`（`settings.go:102`）。
pub fn is_gateway_routing_option_key(key: &str) -> bool {
    GATEWAY_ROUTING_OPTION_KEYS.contains(&key)
}

/// Go 哨兵错误（`store_gateway_revision.go:17-25`）的 Rust 对应物。通过
/// `sqlx::Error::Configuration` 传出，保持仓储层统一的 `sqlx::Error` 签名。
#[derive(Debug)]
pub enum GatewayRevisionError {
    /// Go `ErrGatewayRevisionMissing`：单例行缺失，无法推进水位。调用方
    /// 绝不允许退化到 0 修订号。
    RowMissing,
    /// Go `ErrGatewayRevisionInvalid`：存储的水位 NULL/零/负，不可发布。
    NotPositive(i64),
    /// Go `RecordGatewayConfigOutboxAttempt` / `MarkGatewayConfigOutboxPublished`
    /// 的参数校验失败（`store_gateway_revision.go:146-167`）。
    InvalidOutboxAttempt,
}

impl std::fmt::Display for GatewayRevisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RowMissing => {
                write!(f, "gateway config revision row is missing")
            }
            Self::NotPositive(value) => {
                write!(f, "gateway config revision is not positive: got {value}")
            }
            Self::InvalidOutboxAttempt => {
                write!(f, "invalid outbox publish attempt")
            }
        }
    }
}

impl std::error::Error for GatewayRevisionError {}

fn revision_error(error: GatewayRevisionError) -> sqlx::Error {
    sqlx::Error::Configuration(Box::new(error))
}

// ---------------------------------------------------------------------------
// 单事务 bump：供 `mutate_routing!` 在两个驱动分支里调用
// ---------------------------------------------------------------------------

const BUMP_SQL: &str =
    "UPDATE gateway_config_revisions SET routing_revision = routing_revision + 1 WHERE id = $1";
const READ_BACK_SQL: &str = "SELECT routing_revision FROM gateway_config_revisions WHERE id = $1";
const OUTBOX_INSERT_SQL: &str = "INSERT INTO gateway_config_outboxes (routing_revision, created_at) \
     VALUES ($1, CURRENT_TIMESTAMP)";

/// Go `BumpGatewayRoutingRevision`（`store_gateway_revision.go:78-104`）的
/// SQLite 事务内形式。原子单行 UPDATE 串行化并发；影响行数 != 1 即单例行
/// 缺失；读回校验水位为正；同事务写一条 outbox。
pub async fn bump_routing_revision_sqlite(
    tx: &mut sqlx::SqliteConnection,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(BUMP_SQL)
        .bind(GATEWAY_CONFIG_REVISION_ID)
        .execute(&mut *tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(revision_error(GatewayRevisionError::RowMissing));
    }
    let revision: i64 = sqlx::query_scalar(READ_BACK_SQL)
        .bind(GATEWAY_CONFIG_REVISION_ID)
        .fetch_one(&mut *tx)
        .await?;
    if revision <= 0 {
        return Err(revision_error(GatewayRevisionError::NotPositive(revision)));
    }
    sqlx::query(OUTBOX_INSERT_SQL)
        .bind(revision)
        .execute(&mut *tx)
        .await?;
    Ok(revision)
}

/// [`bump_routing_revision_sqlite`] 的 PostgreSQL 形式，语义逐条一致
/// （单行 UPDATE 行锁天然串行化并发 bump）。
pub async fn bump_routing_revision_postgres(
    tx: &mut sqlx::PgConnection,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(BUMP_SQL)
        .bind(GATEWAY_CONFIG_REVISION_ID)
        .execute(&mut *tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(revision_error(GatewayRevisionError::RowMissing));
    }
    let revision: i64 = sqlx::query_scalar(READ_BACK_SQL)
        .bind(GATEWAY_CONFIG_REVISION_ID)
        .fetch_one(&mut *tx)
        .await?;
    if revision <= 0 {
        return Err(revision_error(GatewayRevisionError::NotPositive(revision)));
    }
    sqlx::query(OUTBOX_INSERT_SQL)
        .bind(revision)
        .execute(&mut *tx)
        .await?;
    Ok(revision)
}

/// Go `MutateGatewayRouting`（`store_gateway_revision.go:111-128`）的等价
/// 原语：`$conn` 在事务体内绑定到驱动连接（`&mut SqliteConnection` /
/// `&mut PgConnection`），`$body` 是 `Result<T, sqlx::Error>` 表达式（与原
/// `transactional!` 约定一致）。body 失败 → 直接回滚，**不** bump；body
/// 成功后、commit 前强制 bump，bump 失败同样整体回滚。修订号与 outbox 同
/// 生共死；一次逻辑变更必须产生恰好一个修订号，因此**不得嵌套**进另一个
/// `mutate_routing!`。
#[macro_export]
macro_rules! mutate_routing {
    ($db:expr, $conn:ident, $body:block) => {
        match $db {
            newapi_storage::Database::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                let outcome: Result<_, sqlx::Error> = async {
                    let $conn = &mut *tx;
                    // match 而非 `?`：body 的 E 经 outcome 的类型注解统一成
                    // sqlx::Error（与原 `transactional!` 的推断路径一致）。
                    match $body {
                        Ok(value) => {
                            $crate::gateway_revision::bump_routing_revision_sqlite(&mut *tx)
                                .await?;
                            Ok(value)
                        }
                        Err(error) => Err(error),
                    }
                }
                .await;
                match outcome {
                    Ok(value) => {
                        tx.commit().await?;
                        Ok(value)
                    }
                    Err(error) => {
                        let _ = tx.rollback().await;
                        Err(error)
                    }
                }
            }
            newapi_storage::Database::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                let outcome: Result<_, sqlx::Error> = async {
                    let $conn = &mut *tx;
                    match $body {
                        Ok(value) => {
                            $crate::gateway_revision::bump_routing_revision_postgres(&mut *tx)
                                .await?;
                            Ok(value)
                        }
                        Err(error) => Err(error),
                    }
                }
                .await;
                match outcome {
                    Ok(value) => {
                        tx.commit().await?;
                        Ok(value)
                    }
                    Err(error) => {
                        let _ = tx.rollback().await;
                        Err(error)
                    }
                }
            }
        }
    };
}

// ---------------------------------------------------------------------------
// 初始化与读侧
// ---------------------------------------------------------------------------

/// Go `InitializeGatewayConfigRevision`（`store_gateway_revision.go:52-71`）：
/// 空表时创建单例行（修订号 1），从不重置或复制已有水位（消费方会看到水位
/// 倒退）；非空表校验单例行存在且水位为正。
pub async fn initialize_gateway_config_revision(db: &Database) -> Result<(), sqlx::Error> {
    let existing: i64 = match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM gateway_config_revisions")
                .fetch_one(pool)
                .await?
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar("SELECT COUNT(*) FROM gateway_config_revisions")
                .fetch_one(pool)
                .await?
        }
    };
    if existing == 0 {
        return match db {
            Database::Sqlite(pool) => sqlx::query(
                "INSERT INTO gateway_config_revisions (id, routing_revision) \
                             VALUES ($1, $2)",
            )
            .bind(GATEWAY_CONFIG_REVISION_ID)
            .bind(1i64)
            .execute(pool)
            .await
            .map(|_| ()),
            Database::Postgres(pool) => sqlx::query(
                "INSERT INTO gateway_config_revisions (id, routing_revision) \
                             VALUES ($1, $2)",
            )
            .bind(GATEWAY_CONFIG_REVISION_ID)
            .bind(1i64)
            .execute(pool)
            .await
            .map(|_| ()),
        };
    }
    let revision: Option<i64> = match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar(READ_BACK_SQL)
                .bind(GATEWAY_CONFIG_REVISION_ID)
                .fetch_optional(pool)
                .await?
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar(READ_BACK_SQL)
                .bind(GATEWAY_CONFIG_REVISION_ID)
                .fetch_optional(pool)
                .await?
        }
    };
    match revision {
        None => Err(revision_error(GatewayRevisionError::RowMissing)),
        Some(value) if value <= 0 => Err(revision_error(GatewayRevisionError::NotPositive(value))),
        Some(_) => Ok(()),
    }
}

/// 读侧消费点（Go：组快照/选择器经 revision 比对缓存新鲜度）：当前已提交
/// 水位。行缺失报 [`GatewayRevisionError::RowMissing`] 而非返回 0
/// （0 的语义是“从未发布”，编造它会掩盖未初始化）。
pub async fn current_gateway_revision(db: &Database) -> Result<i64, sqlx::Error> {
    match db {
        Database::Sqlite(pool) => sqlx::query_scalar(READ_BACK_SQL)
            .bind(GATEWAY_CONFIG_REVISION_ID)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| revision_error(GatewayRevisionError::RowMissing)),
        Database::Postgres(pool) => sqlx::query_scalar(READ_BACK_SQL)
            .bind(GATEWAY_CONFIG_REVISION_ID)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| revision_error(GatewayRevisionError::RowMissing)),
    }
}

// ---------------------------------------------------------------------------
// outbox 发布侧存储（Go publish_gateway_config.go 的存储部分）
// ---------------------------------------------------------------------------

/// Go `ListPendingGatewayConfigOutbox` 的行（`store_gateway_revision.go:132`）。
#[derive(Debug, Clone)]
pub struct GatewayOutboxRow {
    pub id: i64,
    pub routing_revision: i64,
}

/// Go `ListPendingGatewayConfigOutbox`（`store_gateway_revision.go:132-142`）：
/// 最旧的未发布修订，按修订号升序。
pub async fn list_pending_gateway_config_outbox(
    db: &Database,
    limit: i64,
) -> Result<Vec<GatewayOutboxRow>, sqlx::Error> {
    if limit <= 0 {
        return Err(revision_error(GatewayRevisionError::InvalidOutboxAttempt));
    }
    let sql = "SELECT id, routing_revision FROM gateway_config_outboxes \
               WHERE published_at IS NULL ORDER BY routing_revision ASC LIMIT $1";
    match db {
        Database::Sqlite(pool) => {
            let rows = sqlx::query(sql).bind(limit).fetch_all(pool).await?;
            Ok(rows
                .iter()
                .map(|row| GatewayOutboxRow {
                    id: row.try_get("id").unwrap_or_default(),
                    routing_revision: row.try_get("routing_revision").unwrap_or_default(),
                })
                .collect())
        }
        Database::Postgres(pool) => {
            let rows = sqlx::query(sql).bind(limit).fetch_all(pool).await?;
            Ok(rows
                .iter()
                .map(|row| GatewayOutboxRow {
                    id: row.try_get("id").unwrap_or_default(),
                    routing_revision: row.try_get("routing_revision").unwrap_or_default(),
                })
                .collect())
        }
    }
}

/// Go `RecordGatewayConfigOutboxAttempt`（`store_gateway_revision.go:146-155`）：
/// 尝试计数 +1，只记有界的错误类别，不存错误原文。
pub async fn record_gateway_config_outbox_attempt(
    db: &Database,
    id: i64,
    error_class: &str,
) -> Result<(), sqlx::Error> {
    if id <= 0 || error_class.is_empty() || error_class.len() > 64 {
        return Err(revision_error(GatewayRevisionError::InvalidOutboxAttempt));
    }
    let sql = "UPDATE gateway_config_outboxes SET publish_attempts = publish_attempts + 1, \
               last_publish_error_class = $1 WHERE id = $2";
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(sql)
                .bind(error_class)
                .bind(id)
                .execute(pool)
                .await?;
        }
        Database::Postgres(pool) => {
            sqlx::query(sql)
                .bind(error_class)
                .bind(id)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

/// Go `MarkGatewayConfigOutboxPublished`（`store_gateway_revision.go:160-167`）：
/// 幂等，绝不覆写首次成功发布时间戳。`published_at_unix` 是 unix 秒，按仓库
/// 先例经 `datetime(...,'unixepoch')` / `to_timestamp(...)` 写时间戳列。
pub async fn mark_gateway_config_outbox_published(
    db: &Database,
    id: i64,
    published_at_unix: i64,
) -> Result<(), sqlx::Error> {
    if id <= 0 || published_at_unix == 0 {
        return Err(revision_error(GatewayRevisionError::InvalidOutboxAttempt));
    }
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                "UPDATE gateway_config_outboxes SET published_at = \
                         datetime($1, 'unixepoch') WHERE id = $2 AND published_at IS NULL",
            )
            .bind(published_at_unix)
            .bind(id)
            .execute(pool)
            .await?;
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "UPDATE gateway_config_outboxes SET published_at = \
                         to_timestamp($1::BIGINT) WHERE id = $2 AND published_at IS NULL",
            )
            .bind(published_at_unix)
            .bind(id)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}
