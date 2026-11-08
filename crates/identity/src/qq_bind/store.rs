//! QQ 绑定表访问：Go `apps/api/internal/identity/qq_binding.go`。
//!
//! 语句统一用 `$1` 占位符（两个驱动都接受，见 `billing/src/checkin/store.rs`
//! 的同一约定）。所有 `sqlx::query` 的参数都是 `&'static str` 常量。

use newapi_storage::Database;
use rand::{Rng, rngs::OsRng};
use sqlx::Row;

/// Go `QQBindCodeTTL = 5 * time.Minute`（`qq_binding.go:74-77`）。
///
/// 注释里的线上数据（约 12% 的验证码因 3 分钟切不过来而作废）是 TTL 从 3 分钟
/// 放宽到 5 分钟的原因，这里只复刻结果值。
pub const BIND_CODE_TTL_SECONDS: i64 = 5 * 60;

/// Go `bindCodeAlphabet`（`qq_binding.go:81`）：去掉容易混淆的 0/O/o、1/l/I，
/// 共 56 个区分大小写的字母与数字。
pub const BIND_CODE_ALPHABET: &[u8; 56] =
    b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz";

/// Go `generateBindCode` 的码长（`qq_binding.go:87`）。
pub const BIND_CODE_LENGTH: usize = 6;

/// Go `CreateQQBindCode` 的冲突重试上限（`qq_binding.go:190`）。
pub const BIND_CODE_ATTEMPTS: usize = 8;

/// Go `GetQQBindingByUserId`：`First` 查不到行即 `ErrRecordNotFound`。
const BINDING_BY_USER_SQL: &str = "SELECT username, created_at \
     FROM qq_bindings WHERE user_id = $1";

/// Go `GetQQUnbindRecord`：只取解绑时间列。
const UNBIND_AT_SQL: &str = "SELECT unbind_at FROM qq_unbind_records WHERE user_id = $1";

/// Go `CreateQQBindCode` 的作废旧码（`qq_binding.go:182-184`）：
/// 同一用户重复调用会作废此前**未使用**的验证码。
const INVALIDATE_CODES_SQL: &str = "UPDATE qq_bind_codes SET used = $1 \
     WHERE user_id = $2 AND used = $3";

/// Go `CreateQQBindCode` 的冲突判据（`qq_binding.go:196-199`）：仅与尚在
/// 有效期内且未使用的验证码比较——过期码可以复用。
const ACTIVE_CODE_COUNT_SQL: &str = "SELECT COUNT(*) FROM qq_bind_codes \
     WHERE code = $1 AND used = $2 AND expired_at > $3";

/// Go `dbx.DB.Create(bindCode)`：`Used` 带 `default:false` 标签，零值时 GORM
/// 不写该列；这里显式写入，结果等价。
const INSERT_CODE_SQL: &str = "INSERT INTO qq_bind_codes \
     (code, user_id, expired_at, used, created_at) VALUES ($1, $2, $3, $4, $5)";

/// Go `DeleteQQBindingWithTx` 的两段删除（`qq_binding.go:304-309`）：
/// 绑定行与**该用户全部**验证码（不看 `used`）一起物理删除。
const DELETE_BINDING_SQL: &str = "DELETE FROM qq_bindings WHERE user_id = $1";
const DELETE_CODES_SQL: &str = "DELETE FROM qq_bind_codes WHERE user_id = $1";

/// Go `RecordQQUnbind` 的 `tx.Save(&QQUnbindRecord{...})`：主键是 `user_id`，
/// `Save` 对已存在的行走更新，等价于 upsert。
const UPSERT_UNBIND_SQL: &str = "INSERT INTO qq_unbind_records \
     (user_id, unbind_at, created_at) VALUES ($1, $2, $3) \
     ON CONFLICT (user_id) DO UPDATE SET \
     unbind_at = excluded.unbind_at, created_at = excluded.created_at";

/// Go `GetQQBindStatus` 读取的绑定投影（`manage_qqbot.go:357-360`）：
/// 只有 `qq_username` 与 `bound_at` 两个字段会进响应体。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QQBindingView {
    /// Go `binding.Username`：可空列按零值（空串）处理。
    pub username: String,
    /// Go `binding.CreatedAt`：Unix 秒。
    pub bound_at: i64,
}

/// Go `CreateQQBindCode` 成功时返回的一行；`code` 已带 `#` 前缀。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QQBindCode {
    /// Go `bindCode.Code`：落库即 `"#" + 六位验证码`。
    pub code: String,
    /// Go `bindCode.ExpiredAt`：Unix 秒。
    pub expired_at: i64,
}

/// Go `CreateQQBindCode` 的失败分类。Go 直接用 `errors.New(...)` 原文回显；
/// 这里同样逐字保留固定文案，只有数据库故障按仓库约定折叠（由适配层映射到
/// `common.database_error`），不外泄 SQL 文本。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QQBindCodeError {
    /// Go `qq_binding.go:175`：「当前账号已绑定 QQ，请先解绑」。
    AlreadyBound,
    /// Go `RejectQQBindIfInCooldown`：「解绑后需等待冷却时间才能重新绑定，
    /// 剩余 N 秒」。
    Cooldown { remaining_seconds: i64 },
    /// Go `qq_binding.go:207`：「验证码生成失败，请稍后重试」。
    GenerateFailed,
    /// 数据库故障（分类消息，不含驱动文本）。
    Database,
}

/// Go `DeleteQQBinding` / `DeleteQQBindingWithTx` 的失败分类。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QQUnbindError {
    /// Go `qq_binding.go:302`：「id 为空！」。HTTP 路径不可达（用户 ID 来自
    /// 鉴权结果），保留分支只为语义对齐。
    EmptyUserId,
    /// 数据库故障（分类消息，不含驱动文本）。
    Database,
}

pub struct QQBindingRepository {
    /// `pub(super)`：同模块测试直接用它建种子数据；模块外只走方法。
    pub(super) db: Database,
}

/// 把一个只差池类型的事务体展开成两个驱动各自的形式；与
/// `billing/src/checkin/store.rs` 的 `checkin_transaction!` 同一手法。
macro_rules! unbind_transaction {
    ($pool:expr, $user_id:expr, $now:expr) => {{
        let user_id: i64 = $user_id;
        let now: i64 = $now;
        let mut tx = $pool.begin().await.map_err(|_| QQUnbindError::Database)?;
        let outcome: Result<(), QQUnbindError> = async {
            sqlx::query(DELETE_BINDING_SQL)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(|_| QQUnbindError::Database)?;
            // 未使用的验证码必须连坐清除：`ConsumeQQBindCode` 只按 code 查，
            // 留着等于给已解绑账号留一个可用的绑定凭证（`qq_binding.go:294-296`）。
            sqlx::query(DELETE_CODES_SQL)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(|_| QQUnbindError::Database)?;
            sqlx::query(UPSERT_UNBIND_SQL)
                .bind(user_id)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(|_| QQUnbindError::Database)?;
            Ok(())
        }
        .await;
        match outcome {
            Ok(()) => {
                tx.commit().await.map_err(|_| QQUnbindError::Database)?;
                Ok(())
            }
            Err(error) => {
                // 回滚失败同样只归数据库类：客户端文案不变。
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }};
}

impl QQBindingRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `GetQQBindStatus` 的读取分支（`manage_qqbot.go:349-350`）：
    /// `err == nil && binding != nil` 才算已绑定。
    ///
    /// 查询失败时 Go 静默按未绑定处理（状态接口永不报错），这里同样只回
    /// `None`，但记一条分类告警——不让 SQL 文本外泄，也不改变调用方看到的
    /// 结果。
    pub async fn bind_status(&self, user_id: i64) -> Option<QQBindingView> {
        match self.binding_by_user(user_id).await {
            Ok(view) => view,
            Err(_) => {
                tracing::warn!(
                    event = "qq_binding_lookup_failed",
                    user_id,
                    category = "database",
                    "QQ binding lookup failed; Go treats this as unbound"
                );
                None
            }
        }
    }

    /// Go `GetQQBindingByUserId`：行不存在为 `Ok(None)`，驱动错误为 `Err`。
    /// 可空列按 Go 结构体的零值处理（`username` 空串、`created_at` 0）。
    async fn binding_by_user(&self, user_id: i64) -> Result<Option<QQBindingView>, sqlx::Error> {
        let row = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(BINDING_BY_USER_SQL)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Database::Postgres(pool) => {
                sqlx::query(BINDING_BY_USER_SQL)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        Ok(row.map(|row| QQBindingView {
            username: row
                .try_get::<Option<String>, _>("username")?
                .unwrap_or_default(),
            bound_at: row
                .try_get::<Option<i64>, _>("created_at")?
                .unwrap_or_default(),
        }))
    }

    /// Go `CreateQQBindCode`（`qq_binding.go:170-221`）。
    ///
    /// 分支顺序即契约：已绑定 → 冷却 → 作废旧码 → 生成。`rebind_cooldown_seconds`
    /// 由调用方从 `qq_bot_setting` 读入（Go 是 `GetQQBotSetting` 同步进 identity
    /// 的进程全局），`<= 0` 表示关闭冷却。
    pub async fn create_bind_code(
        &self,
        user_id: i64,
        rebind_cooldown_seconds: i64,
    ) -> Result<QQBindCode, QQBindCodeError> {
        // 步骤 1：已绑定的用户不再生成验证码。读取失败同样按未绑定继续
        // （Go `err == nil` 才算已绑定）。
        if self.bind_status(user_id).await.is_some() {
            return Err(QQBindCodeError::AlreadyBound);
        }
        // 步骤 2：解绑冷却（Go `RejectQQBindIfInCooldown`）：`<= 0` 时 Go 在读
        // 记录之前就返回；无记录同样直接放行。
        if rebind_cooldown_seconds > 0 {
            if let Some(unbind_at) = self.unbind_at(user_id).await? {
                let allowed_at = unbind_at.saturating_add(rebind_cooldown_seconds);
                let now = unix_seconds();
                if now < allowed_at {
                    return Err(QQBindCodeError::Cooldown {
                        remaining_seconds: allowed_at - now,
                    });
                }
            }
        }
        // 步骤 3：作废该用户此前未使用的验证码。Go 吞掉这个 UPDATE 的错误；
        // 这里归入 `Database`——同样的故障下后续插入也必然失败，客户端看到的
        // 都是错误信封，只是文案从泄漏的 SQL 变成固定分类。
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(INVALIDATE_CODES_SQL)
                    .bind(true)
                    .bind(user_id)
                    .bind(false)
                    .execute(pool)
                    .await
                    .map_err(|_| QQBindCodeError::Database)?;
            }
            Database::Postgres(pool) => {
                sqlx::query(INVALIDATE_CODES_SQL)
                    .bind(true)
                    .bind(user_id)
                    .bind(false)
                    .execute(pool)
                    .await
                    .map_err(|_| QQBindCodeError::Database)?;
            }
        }
        let now = unix_seconds();
        let expired_at = now + BIND_CODE_TTL_SECONDS;
        // 步骤 4：生成不冲突的验证码，最多重试 8 次；冲突判定只与「未使用且
        // 未过期」的行比较（Go `qq_binding.go:189-205`）。COUNT 失败归
        // `Database`，理由同步骤 3。
        for _ in 0..BIND_CODE_ATTEMPTS {
            let candidate = generate_bind_code();
            let prefixed = format!("#{candidate}");
            let conflicts = match &self.db {
                Database::Sqlite(pool) => {
                    sqlx::query_scalar::<_, i64>(ACTIVE_CODE_COUNT_SQL)
                        .bind(&prefixed)
                        .bind(false)
                        .bind(now)
                        .fetch_one(pool)
                        .await
                }
                Database::Postgres(pool) => {
                    sqlx::query_scalar::<_, i64>(ACTIVE_CODE_COUNT_SQL)
                        .bind(&prefixed)
                        .bind(false)
                        .bind(now)
                        .fetch_one(pool)
                        .await
                }
            }
            .map_err(|_| QQBindCodeError::Database)?;
            if conflicts > 0 {
                continue;
            }
            match &self.db {
                Database::Sqlite(pool) => {
                    sqlx::query(INSERT_CODE_SQL)
                        .bind(&prefixed)
                        .bind(user_id)
                        .bind(expired_at)
                        .bind(false)
                        .bind(now)
                        .execute(pool)
                        .await
                        .map_err(|_| QQBindCodeError::Database)?;
                }
                Database::Postgres(pool) => {
                    sqlx::query(INSERT_CODE_SQL)
                        .bind(&prefixed)
                        .bind(user_id)
                        .bind(expired_at)
                        .bind(false)
                        .bind(now)
                        .execute(pool)
                        .await
                        .map_err(|_| QQBindCodeError::Database)?;
                }
            }
            return Ok(QQBindCode {
                code: prefixed,
                expired_at,
            });
        }
        Err(QQBindCodeError::GenerateFailed)
    }

    /// Go `DeleteQQBinding` + `DeleteQQBindingWithTx` +
    /// `RecordQQUnbind`（`qq_binding.go:285-311`）：
    /// 一个事务里删绑定行、删该用户全部验证码、upsert 解绑记录。
    pub async fn delete_binding(&self, user_id: i64) -> Result<(), QQUnbindError> {
        if user_id == 0 {
            return Err(QQUnbindError::EmptyUserId);
        }
        let now = unix_seconds();
        match &self.db {
            Database::Sqlite(pool) => unbind_transaction!(pool, user_id, now),
            Database::Postgres(pool) => unbind_transaction!(pool, user_id, now),
        }
    }

    /// Go `GetQQUnbindRecord` 的解绑时间列；行不存在为 `None`。
    async fn unbind_at(&self, user_id: i64) -> Result<Option<i64>, QQBindCodeError> {
        let row = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar::<_, Option<i64>>(UNBIND_AT_SQL)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar::<_, Option<i64>>(UNBIND_AT_SQL)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
            }
        };
        // Go 的 `RejectQQBindIfInCooldown` 在查询出错时按「无记录、直接放行」
        // 处理；本端口把读取失败归入 `Database`（后续写路径同样会失败），
        // 不静默放行。
        row.map_err(|_| QQBindCodeError::Database)
            .map(|row| row.flatten())
    }
}

/// Go `generateBindCode`（`qq_binding.go:84-95`）：六位、每位在 56 字符的
/// 字母表上均匀取。Go 用 `crypto/rand.Int`，这里用 `OsRng::gen_range`——
/// 同为密码学随机源；`gen_range` 的取模偏差在 56 的量级下可忽略
/// （约 2^-64，Go 的 `Intn` 是无偏的，这是唯一偏差点）。
fn generate_bind_code() -> String {
    let mut rng = OsRng;
    let alphabet = BIND_CODE_ALPHABET.len();
    (0..BIND_CODE_LENGTH)
        .map(|_| BIND_CODE_ALPHABET[rng.gen_range(0..alphabet)] as char)
        .collect()
}

/// Go `time.Now().Unix()`（秒）。
fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}
