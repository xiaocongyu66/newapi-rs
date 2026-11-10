//! OAuth 登录/绑定所需的用户存储操作：Go `identity/store_users.go` 与
//! `store_users_lifecycle.go` 的选中子集——按绑定列查用户、绑定列占用
//! 检查、只写单列的绑定更新、OAuth 用户的查找或创建（事务内创建 +
//! 绑定，提交后 `FinalizeOAuthUserCreation`），以及邮箱绑定
//! （`EmailBind` → `BindEmailToUser`）。
//!
//! 与 Go 的对齐点：
//! - 占用检查的软删可见性逐字对齐（GitHub/Discord/WeChat 用 `Unscoped`，
//!   OIDC/Telegram 用默认作用域，LinuxDO 用 `Unscoped`）；
//! - `UpdateUserBindColumn` 只更新白名单内的单列，绝不全快照写回；
//! - 用户创建走 `User.InsertWithTx` 语义：事务内邮箱可用性检查
//!   （PG 加 advisory lock 串行同邮箱写）、quota 取选项值、随机 4 位
//!   aff_code、默认 setting；
//! - 邮箱绑定复刻 `BindEmailToUser` 的事务形状（同一 advisory lock）。

// profile! 宏在调用点展开：Row trait 与 UserProfile 需在此作用域可见。
use crate::users::{UserProfile, profile};
use newapi_storage::Database;
use sqlx::Row;

/// Go `userBindColumns`（`store_users_lifecycle.go:121-127`）。
const BIND_COLUMNS: [&str; 5] = [
    "github_id",
    "discord_id",
    "oidc_id",
    "linux_do_id",
    "wechat_id",
];

/// Go `UserNameMaxLength = 20`。
pub const USER_NAME_MAX_CHARS: usize = 20;

// 显式列清单，禁止 SELECT *；旧库的 INTEGER 列显式提升 BIGINT。
const USER_BY_BIND_COLUMN_SQL: &str = r#"SELECT CAST(id AS BIGINT) AS id, username, display_name, CAST(role AS BIGINT) AS role, CAST(status AS BIGINT) AS status, email, github_id, discord_id, oidc_id, wechat_id, telegram_id, "group", CAST(quota AS BIGINT) AS quota, CAST(used_quota AS BIGINT) AS used_quota, CAST(request_count AS BIGINT) AS request_count, aff_code, CAST(aff_count AS BIGINT) AS aff_count, CAST(aff_quota AS BIGINT) AS aff_quota, CAST(aff_history AS BIGINT) AS aff_history_quota, CAST(inviter_id AS BIGINT) AS inviter_id, linux_do_id, setting, stripe_customer, CAST(auth_version AS BIGINT) AS auth_version FROM users"#;

/// `FillUserById`（EmailBind 路径）：固定 WHERE，静态字面量。
const USER_BY_ID_SQL: &str = r#"SELECT CAST(id AS BIGINT) AS id, username, display_name, CAST(role AS BIGINT) AS role, CAST(status AS BIGINT) AS status, email, github_id, discord_id, oidc_id, wechat_id, telegram_id, "group", CAST(quota AS BIGINT) AS quota, CAST(used_quota AS BIGINT) AS used_quota, CAST(request_count AS BIGINT) AS request_count, aff_code, CAST(aff_count AS BIGINT) AS aff_count, CAST(aff_quota AS BIGINT) AS aff_quota, CAST(aff_history AS BIGINT) AS aff_history_quota, CAST(inviter_id AS BIGINT) AS inviter_id, linux_do_id, setting, stripe_customer, CAST(auth_version AS BIGINT) AS auth_version FROM users WHERE id = $1 AND deleted_at IS NULL"#;

/// `GetUserByOAuthBinding`：绑定行 → 用户行；固定 WHERE，静态字面量。
const USER_BY_CUSTOM_BINDING_SQL: &str = r#"SELECT CAST(id AS BIGINT) AS id, username, display_name, CAST(role AS BIGINT) AS role, CAST(status AS BIGINT) AS status, email, github_id, discord_id, oidc_id, wechat_id, telegram_id, "group", CAST(quota AS BIGINT) AS quota, CAST(used_quota AS BIGINT) AS used_quota, CAST(request_count AS BIGINT) AS request_count, aff_code, CAST(aff_count AS BIGINT) AS aff_count, CAST(aff_quota AS BIGINT) AS aff_quota, CAST(aff_history AS BIGINT) AS aff_history_quota, CAST(inviter_id AS BIGINT) AS inviter_id, linux_do_id, setting, stripe_customer, CAST(auth_version AS BIGINT) AS auth_version FROM users WHERE id = (SELECT user_id FROM user_oauth_bindings WHERE provider_id = $1 AND provider_user_id = $2) AND deleted_at IS NULL"#;

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

/// 软删过滤后的用户资料（`UserProfile` 形状，复用 crate 内已有投影）。
pub type StoreUser = crate::users::UserProfile;

/// 查询/写入失败分类；不携带 SQL 文本。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    Storage,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("oauth user store failure")
    }
}

impl std::error::Error for StoreError {}

impl From<sqlx::Error> for StoreError {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}

/// OAuth 用户的查找或创建输入；`bind_column` 为空表示 generic 提供商
/// （绑定落 user_oauth_bindings，与用户行同事务创建）。
pub struct NewOAuthUser<'a> {
    pub username: &'a str,
    pub display_name: &'a str,
    pub email: &'a str,
    pub bind_column: &'a str,
    pub provider_user_id: &'a str,
    pub custom_provider_id: i64,
    pub inviter_id: i64,
    /// Go `User.InsertWithTx` 写入的 `common.QuotaForNewUser`。
    pub quota: i64,
    pub created_at: i64,
}

/// Go `BindEmailToUser`（`store_users.go:512-526`）：事务内邮箱互斥检查
/// （排除本人）+ 单列更新；宏展开为具体后端代码（同上，泛型执行器上的
/// f64/tuple 绑定无法对任意 `DB: Database` 成立）。
macro_rules! bind_email_body {
    ($pool:expr, $dialect:expr, $user_id:expr, $email:expr) => {{
        let mut tx = match $dialect {
            Dialect::Sqlite => $pool.begin_with("BEGIN IMMEDIATE").await?,
            Dialect::Postgres => $pool.begin().await?,
        };
        // Go `withNormalizedEmailLock`：PG advisory lock 串行同邮箱写。
        if !$email.is_empty() && $dialect == Dialect::Postgres {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
                .bind($email)
                .execute(&mut *tx)
                .await?;
        }
        if !$email.is_empty() {
            let taken: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = $1 AND id <> $2 AND deleted_at IS NULL)",
            )
            .bind($email)
            .bind($user_id)
            .fetch_one(&mut *tx)
            .await?;
            if taken {
                return Err(EmailBindError::EmailTaken);
            }
        }
        sqlx::query("UPDATE users SET email = $1 WHERE id = $2")
            .bind($email)
            .bind($user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok::<(), EmailBindError>(())
    }};
}

/// Go `User.InsertWithTx` + 提供商绑定列的宏体（两个后端共享形状；
/// 时间列 created_at 是 bigint，直接绑定）。
macro_rules! create_user_body {
    ($pool:expr, $dialect:expr, $input:expr, $aff_code:expr, $setting:expr) => {{
        let mut tx = match $dialect {
            Dialect::Sqlite => $pool.begin_with("BEGIN IMMEDIATE").await?,
            Dialect::Postgres => $pool.begin().await?,
        };
        // Go `withNormalizedEmailLock`：PG advisory lock 串行同邮箱写；
        // SQLite 单写者天然串行。
        if !$input.email.is_empty() && $dialect == Dialect::Postgres {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
                .bind($input.email)
                .execute(&mut *tx)
                .await?;
        }
        // 事务内邮箱可用性复查（Go `ensureEmailAvailableWithTx`）。
        if !$input.email.is_empty() {
            let taken: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = $1 AND deleted_at IS NULL)",
            )
            .bind($input.email)
            .fetch_one(&mut *tx)
            .await?;
            if taken {
                return Err(CreateUserError::EmailTaken);
            }
        }
        let inserted: i64 = sqlx::query_scalar(
            "INSERT INTO users (
                username,password,display_name,role,status,email,github_id,discord_id,
                oidc_id,wechat_id,telegram_id,quota,used_quota,request_count,\"group\",
                aff_code,aff_count,aff_quota,aff_history,inviter_id,deleted_at,
                linux_do_id,setting,remark,stripe_customer,created_at,last_login_at,auth_version
            ) VALUES (
                $1,'',$2,1,1,$3,$4,$4,$4,$4,$4,$5,0,0,'default',
                $6,0,0,0,$7,NULL,
                '',$8,'','',$9,0,1
            ) RETURNING CAST(id AS BIGINT)",
        )
        .bind($input.username)
        .bind($input.display_name)
        .bind($input.email)
        // Go：非目标提供商的绑定列保持零值空串；占位共用 $4 时由
        // 调用方按 bind_column 单列覆写（见下方 UPDATE）。
        .bind("")
        .bind($input.quota)
        .bind($aff_code)
        .bind($input.inviter_id)
        .bind($setting)
        .bind($input.created_at)
        .fetch_one(&mut *tx)
        .await?;
        // 绑定列（generic 走绑定行，其余单列 UPDATE——保持与 Go 的
        // `SetProviderUserID` + Updates(map) 等价的最终状态）。
        if !$input.bind_column.is_empty() {
            // `bind_column` 来自 ResolvedProvider 的固定常量 / wechat 字面量；
            // AssertSqlSafe 记录该审计。
            let sql = format!("UPDATE users SET {} = $1 WHERE id = $2", $input.bind_column);
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind($input.provider_user_id)
                .bind(inserted)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query(
                "INSERT INTO user_oauth_bindings (user_id,provider_id,provider_user_id,created_at) \
                 VALUES ($1,$2,$3,CURRENT_TIMESTAMP)",
            )
            .bind(inserted)
            .bind($input.custom_provider_id)
            .bind($input.provider_user_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok::<i64, CreateUserError>(inserted)
    }};
}

#[derive(Clone)]
pub struct OAuthUserStore {
    db: Database,
}

impl OAuthUserStore {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `Is{Provider}IdAlreadyTaken`：按提供商的软删可见性逐字对齐。
    /// GitHub/Discord/WeChat/LinuxDO 用 `Unscoped`（软删行也算占用），
    /// OIDC 用默认作用域（`store_users.go:1014`），Telegram 走
    /// external_identity_claims（见 `claim_subject_owner`）。
    pub async fn bind_id_taken(&self, column: &str, value: &str) -> Result<bool, StoreError> {
        if value.is_empty() {
            return Ok(false);
        }
        let unscoped = matches!(
            column,
            "github_id" | "discord_id" | "wechat_id" | "linux_do_id"
        );
        // `column` 来自固定白名单（ResolvedProvider 的常量 / 本模块
        // 调用点），经 AssertSqlSafe 显式审计。
        let sql = if unscoped {
            format!(r#"SELECT EXISTS(SELECT 1 FROM users WHERE {column} = $1)"#)
        } else {
            format!(
                r#"SELECT EXISTS(SELECT 1 FROM users WHERE {column} = $1 AND deleted_at IS NULL)"#
            )
        };
        let taken: bool = backend!(&self.db, pool, {
            sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
                .bind(value)
                .fetch_one(pool)
                .await?
        });
        Ok(taken)
    }

    /// Go `IsWeChatIdAlreadyTaken`（`store_users_lifecycle.go:195-197`）：
    /// `Unscoped().Find().RowsAffected == 1`——注意 Go 的怪癖是"恰好一行"，
    /// 多于一行返回 false；历史数据正常时等价于 EXISTS。
    pub async fn wechat_id_taken(&self, wechat_id: &str) -> Result<bool, StoreError> {
        if wechat_id.is_empty() {
            return Ok(false);
        }
        let count: i64 = backend!(&self.db, pool, {
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE wechat_id = $1")
                .bind(wechat_id)
                .fetch_one(pool)
                .await?
        });
        Ok(count == 1)
    }

    /// Go `FillUserBy{GitHub,Discord,Oidc,WeChat,LinuxDO}Id`：软删作用域
    /// 的 First（GORM 默认排除软删）。找不到返回 `None`（Go 把行保持
    /// 零值、调用方以 `Id == 0` 判定"用户已注销"）。
    pub async fn user_by_bind_column(
        &self,
        column: &str,
        value: &str,
    ) -> Result<Option<StoreUser>, StoreError> {
        // `column` 来自固定白名单（见 bind_id_taken 注释）。
        let sql = format!("{USER_BY_BIND_COLUMN_SQL} WHERE {column} = $1 AND deleted_at IS NULL");
        let user: Option<StoreUser> = backend!(&self.db, pool, {
            let row = sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(value)
                .fetch_optional(pool)
                .await?;
            row.map(|row| Ok::<_, sqlx::Error>(profile!(row)))
                .transpose()?
        });
        Ok(user)
    }

    /// Go `FillUserByTelegramId`：找不到时返回固定中文文案
    /// （`store_users.go:990-999`），由调用方原样回显。
    pub async fn user_by_telegram_id(
        &self,
        telegram_id: &str,
    ) -> Result<Option<StoreUser>, StoreError> {
        self.user_by_bind_column("telegram_id", telegram_id).await
    }

    /// Go `FillUserById`（`manage_users.go` EmailBind 路径）。
    pub async fn user_by_id(&self, user_id: i64) -> Result<Option<StoreUser>, StoreError> {
        let user: Option<StoreUser> = backend!(&self.db, pool, {
            let row = sqlx::query(USER_BY_ID_SQL)
                .bind(user_id)
                .fetch_optional(pool)
                .await?;
            row.map(|row| Ok::<_, sqlx::Error>(profile!(row)))
                .transpose()?
        });
        Ok(user)
    }

    /// Go `GetMaxUserId`（`store_users_lifecycle.go:58-62`）：
    /// `Unscoped().Last(&user)` = 按主键倒序取第一行（含软删）。
    pub async fn max_user_id(&self) -> Result<i64, StoreError> {
        let id: Option<i64> = backend!(&self.db, pool, {
            sqlx::query_scalar("SELECT CAST(MAX(id) AS BIGINT) FROM users")
                .fetch_optional(pool)
                .await?
        });
        Ok(id.unwrap_or(0))
    }

    /// Go `CheckUserExistOrDeleted`（username 分支）：软删行也算存在。
    pub async fn username_taken(&self, username: &str) -> Result<bool, StoreError> {
        let taken: bool = backend!(&self.db, pool, {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
                .bind(username)
                .fetch_one(pool)
                .await?
        });
        Ok(taken)
    }

    /// Go `GetUserIdByAffCode`（`store_users.go:424-431`）：`First` 按
    /// aff_code 命中（唯一索引），软删作用域遵循 GORM 默认排除。
    pub async fn aff_code_owner(&self, aff_code: &str) -> Result<i64, StoreError> {
        if aff_code.is_empty() {
            return Ok(0);
        }
        let id: Option<i64> = backend!(&self.db, pool, {
            sqlx::query_scalar(
                r#"SELECT CAST(id AS BIGINT) FROM users WHERE aff_code = $1 AND deleted_at IS NULL LIMIT 1"#,
            )
            .bind(aff_code)
            .fetch_optional(pool)
            .await?
        });
        Ok(id.unwrap_or(0))
    }

    /// Go `UpdateUserBindColumn`（`store_users_lifecycle.go:133-141`）：
    /// 白名单单列更新；`telegram_id` 不在白名单（走事务内条件更新）。
    pub async fn update_bind_column(
        &self,
        user_id: i64,
        column: &str,
        value: &str,
    ) -> Result<(), StoreError> {
        if user_id <= 0 {
            // Go："id 为空！"由 HTTP 层在鉴权后必不为 0；防御分支折叠。
            return Err(StoreError::Storage);
        }
        if !BIND_COLUMNS.contains(&column) {
            return Err(StoreError::Storage);
        }
        // `column` 已过 BIND_COLUMNS 白名单；AssertSqlSafe 记录该审计。
        let sql = format!("UPDATE users SET {column} = $1 WHERE id = $2");
        backend!(&self.db, pool, {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(value)
                .bind(user_id)
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    /// generic 绑定的占用检查（Go `IsProviderUserIdTaken`，
    /// `bind_oauth.go:58-62`）。
    pub async fn custom_binding_taken(
        &self,
        provider_id: i64,
        provider_user_id: &str,
    ) -> Result<bool, StoreError> {
        let taken: bool = backend!(&self.db, pool, {
            sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM user_oauth_bindings \
                 WHERE provider_id = $1 AND provider_user_id = $2)",
            )
            .bind(provider_id)
            .bind(provider_user_id)
            .fetch_one(pool)
            .await?
        });
        Ok(taken)
    }

    /// Go `GetUserByOAuthBinding`：绑定行 → 用户行；用户缺失（软删）时
    /// Go 报错，这里返回 `None` 由调用方折叠为存储分类。
    pub async fn user_by_custom_binding(
        &self,
        provider_id: i64,
        provider_user_id: &str,
    ) -> Result<Option<StoreUser>, StoreError> {
        let user: Option<StoreUser> = backend!(&self.db, pool, {
            let row = sqlx::query(USER_BY_CUSTOM_BINDING_SQL)
                .bind(provider_id)
                .bind(provider_user_id)
                .fetch_optional(pool)
                .await?;
            row.map(|row| Ok::<_, sqlx::Error>(profile!(row)))
                .transpose()?
        });
        Ok(user)
    }

    /// Go `UpdateUserOAuthBinding`（`bind_oauth.go:109-131`）：新账号被
    /// 他人占用即失败；本人已有绑定则原地改写，否则插入。
    pub async fn update_custom_binding(
        &self,
        user_id: i64,
        provider_id: i64,
        new_provider_user_id: &str,
    ) -> Result<(), StoreError> {
        let owner: Option<i64> = backend!(&self.db, pool, {
            sqlx::query_scalar(
                "SELECT CAST(user_id AS BIGINT) FROM user_oauth_bindings \
                 WHERE provider_id = $1 AND provider_user_id = $2",
            )
            .bind(provider_id)
            .bind(new_provider_user_id)
            .fetch_optional(pool)
            .await?
        });
        if owner.is_some_and(|owner| owner != user_id) {
            // Go："this OAuth account is already bound to another user"；
            // HTTP 层已在前面用 IsUserIDTaken 拦截，这里是竞态兜底。
            return Err(StoreError::Storage);
        }
        let existing: Option<i64> = backend!(&self.db, pool, {
            sqlx::query_scalar(
                "SELECT CAST(id AS BIGINT) FROM user_oauth_bindings \
                 WHERE user_id = $1 AND provider_id = $2",
            )
            .bind(user_id)
            .bind(provider_id)
            .fetch_optional(pool)
            .await?
        });
        match existing {
            Some(_) => {
                backend!(&self.db, pool, {
                    sqlx::query(
                        "UPDATE user_oauth_bindings SET provider_user_id = $1 \
                         WHERE user_id = $2 AND provider_id = $3",
                    )
                    .bind(new_provider_user_id)
                    .bind(user_id)
                    .bind(provider_id)
                    .execute(pool)
                    .await?;
                });
                Ok(())
            }
            None => {
                backend!(&self.db, pool, {
                    sqlx::query(
                        "INSERT INTO user_oauth_bindings (user_id,provider_id,provider_user_id,created_at) \
                         VALUES ($1,$2,$3,CURRENT_TIMESTAMP)",
                    )
                    .bind(user_id)
                    .bind(provider_id)
                    .bind(new_provider_user_id)
                    .execute(pool)
                    .await?;
                });
                Ok(())
            }
        }
    }

    /// Go `findOrCreateOAuthUser` 的已存在分支按 legacy id 迁移：
    /// `UpdateGitHubId`（`store_users.go:963-965`）。
    pub async fn update_github_id(&self, user_id: i64, new_id: &str) -> Result<(), StoreError> {
        backend!(&self.db, pool, {
            sqlx::query("UPDATE users SET github_id = $1 WHERE id = $2")
                .bind(new_id)
                .bind(user_id)
                .execute(pool)
                .await?;
        });
        Ok(())
    }

    /// Go `EnsureEmailAvailable`（含 exclude 用户）：`Ok(false)` = 已占用。
    pub async fn email_available(
        &self,
        email: &str,
        exclude_user_id: i64,
    ) -> Result<bool, StoreError> {
        if email.is_empty() {
            return Ok(true);
        }
        let available: bool = backend!(&self.db, pool, {
            if exclude_user_id > 0 {
                sqlx::query_scalar(
                    "SELECT NOT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = $1 AND id <> $2 AND deleted_at IS NULL)",
                )
                .bind(email)
                .bind(exclude_user_id)
                .fetch_one(pool)
                .await?
            } else {
                sqlx::query_scalar(
                    "SELECT NOT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = $1 AND deleted_at IS NULL)",
                )
                .bind(email)
                .fetch_one(pool)
                .await?
            }
        });
        Ok(available)
    }

    /// Go `findOrCreateOAuthUser` 的事务创建（`handle_oauth.go:371-427`）：
    /// 用户行 + 绑定（单列或 custom 绑定行）在一个事务提交；email 可用性
    /// 在事务内复查（PG advisory lock 串行同邮箱写，与 Go
    /// `withNormalizedEmailLock` 一致）。邮箱占用返回
    /// [`CreateUserError::EmailTaken`]。
    pub async fn create_oauth_user(
        &self,
        input: &NewOAuthUser<'_>,
        aff_code: &str,
        setting: &str,
    ) -> Result<i64, CreateUserError> {
        let dialect = Dialect::of(&self.db);
        backend!(&self.db, pool, {
            create_user_body!(pool, dialect, input, aff_code, setting)
        })
    }

    /// Go `WeChatAuth` 的用户创建（`bind_wechat.go:88-109`）：wechat_id
    /// 直接随用户行插入，无独立绑定事务。
    pub async fn create_wechat_user(
        &self,
        username: &str,
        display_name: &str,
        wechat_id: &str,
        quota: i64,
        created_at: i64,
        aff_code: &str,
        setting: &str,
    ) -> Result<i64, CreateUserError> {
        let input = NewOAuthUser {
            username,
            display_name,
            email: "",
            bind_column: "wechat_id",
            provider_user_id: wechat_id,
            custom_provider_id: 0,
            inviter_id: 0,
            quota,
            created_at,
        };
        let dialect = Dialect::of(&self.db);
        backend!(&self.db, pool, {
            create_user_body!(pool, dialect, &input, aff_code, setting)
        })
    }

    /// Go `EmailBind` → `BindEmailToUser`：事务内邮箱互斥检查 + 单列更新
    /// （`store_users.go:512-526`）。
    pub async fn bind_email(&self, user_id: i64, email: &str) -> Result<(), EmailBindError> {
        let dialect = Dialect::of(&self.db);
        backend!(&self.db, pool, {
            bind_email_body!(pool, dialect, user_id, email)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateUserError {
    EmailTaken,
    Storage,
}

impl From<sqlx::Error> for CreateUserError {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}

impl std::fmt::Display for CreateUserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("oauth user creation failed")
    }
}

impl std::error::Error for CreateUserError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailBindError {
    EmailTaken,
    Storage,
}

impl From<sqlx::Error> for EmailBindError {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}

impl std::fmt::Display for EmailBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("email bind failed")
    }
}

impl std::error::Error for EmailBindError {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Sqlite,
    Postgres,
}

impl Dialect {
    fn of(db: &Database) -> Self {
        match db {
            Database::Sqlite(_) => Self::Sqlite,
            Database::Postgres(_) => Self::Postgres,
        }
    }
}

/// Go `common.GetRandomString(4)` 的字符集（字母 + 数字）。
pub fn random_aff_code() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..4)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}
