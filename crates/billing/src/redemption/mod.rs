//! 兑换码管理端域：记录读写、码生成与列表筛选。
//!
//! Go references:
//! - `apps/api/internal/billing/redeem_code.go`（7 个管理端 handler 的仓储层）
//! - `apps/api/internal/billing/store_redemption.go`（`Redemption` 记录、
//!   `QueryAllRedemptions` / `QueryRedemptions` / `GetRedemptionById` /
//!   `DeleteRedemptionById`）
//! - `apps/api/internal/billing/purge_redemptions.go`（`DeleteInvalidRedemptions`）
//! - `apps/api/internal/common/utils.go:144`（`GetUUID`）
//!
//! 本模块只覆盖管理端 CRUD；兑换的消费链路（用户 topup 时的 `Redeem` 核销）
//! 属 billing 另一条流程，不在本切片内。
//!
//! ## GORM 行为映射
//!
//! - 软删除：`Redemption` 带 `gorm.DeletedAt`，所有读/更新都隐式附加
//!   `deleted_at IS NULL`；`Delete` 与 `DeleteInvalidRedemptions` 只是置
//!   `deleted_at`（`CURRENT_TIMESTAMP` 等价 Go 写入的 time.Time），不物理删除。
//! - 零值省略：GORM `Create` 对带 `default` 标签的零值字段省略插入、回退到
//!   列默认值（`status` 默认 1，`quota` 默认 100），`AddRedemption` 构造的
//!   记录 status 恒为 0，因此插入从不写 status；quota 为 0 时同样省略，
//!   用 `COALESCE(NULLIF($4,0),100)` 复刻这一行为。无默认标签的零值列
//!   （redeemed_time/created_time/used_user_id）按 0 显式写入。
//! - `Update`：GORM `Select("name","status","quota","redeemed_time",
//!   "expired_time")` 强制五列全写（含零值），未变化的列由 handler 用从库
//!   里读出的原值回填，与本仓储的 `RedemptionUpdate` 同构。

use newapi_storage::Database;
use rand::RngCore;
use rand::rngs::OsRng;
use sqlx::Row;
use uuid::Builder;

/// Go `common.RedemptionCodeStatusEnabled`（constants.go:250）。
pub const REDEMPTION_STATUS_ENABLED: i64 = 1;
/// Go `common.RedemptionCodeStatusDisabled`（constants.go:251）。
pub const REDEMPTION_STATUS_DISABLED: i64 = 2;
/// Go `common.RedemptionCodeStatusUsed`（constants.go:252）。
pub const REDEMPTION_STATUS_USED: i64 = 3;

/// Go `billing.Redemption` 的列字段；API 边界字段（`quota_display` 由
/// handler 用额度展示快照换算；`count` 只存在于请求体）不落库，故不在记录内。
///
/// 兑换码本身是凭据：`Debug` 打码，避免落日志。
#[derive(Clone, Eq, PartialEq)]
pub struct RedemptionRecord {
    pub id: i64,
    pub user_id: i64,
    pub key: String,
    pub status: i64,
    pub name: String,
    pub quota: i64,
    pub redeemed_time: i64,
    pub created_time: i64,
    pub used_user_id: i64,
    pub expired_time: i64,
}

impl std::fmt::Debug for RedemptionRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedemptionRecord")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("key", &"<redacted>")
            .field("status", &self.status)
            .field("name", &self.name)
            .field("quota", &self.quota)
            .field("expired_time", &self.expired_time)
            .finish_non_exhaustive()
    }
}

/// `AddRedemption` 单条插入的输入；`user_id` 取管理员 id（Go `c.GetInt("id")`）。
pub struct NewRedemption {
    pub user_id: i64,
    pub key: String,
    pub name: String,
    pub quota: i64,
    /// 过期时间，0 表示不过期。
    pub expired_time: i64,
}

/// `Redemption.Update` 的 GORM `Select` 五列；全量更新与 status_only 都走
/// 同一条 UPDATE，未变化的列由调用方回填原值。
pub struct RedemptionUpdate {
    pub name: String,
    pub status: i64,
    pub quota: i64,
    pub redeemed_time: i64,
    pub expired_time: i64,
}

/// `SearchRedemptions` 的 `status` 参数语义（Go `QueryRedemptions` 的 switch
/// 只认这四个值，其余值与缺省都不加条件）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedemptionStatusFilter {
    /// 未传或未识别：不加条件（Go 的 switch 无 default 分支）。
    None,
    /// `"1"`：启用且未过期（`expired_time = 0` 即永不过期）。
    Enabled,
    /// `"2"`：已禁用。
    Disabled,
    /// `"3"`：已使用。
    Used,
    /// `"expired"`：启用但已过过期时间（不改 status 的过期视图）。
    Expired,
}

impl RedemptionStatusFilter {
    pub fn from_query(status: &str) -> Self {
        match status {
            "expired" => Self::Expired,
            "1" => Self::Enabled,
            "2" => Self::Disabled,
            "3" => Self::Used,
            _ => Self::None,
        }
    }
}

/// Go `common.GetUUID`：UUIDv4 去横线的 32 位小写 hex，长度与 `char(32)`
/// 列一致。OsRng 故障（Go 等价路径会 panic）在这里映射为 `None`，由
/// handler 折叠成创建失败。
pub fn generate_redemption_key() -> Option<String> {
    let mut bytes = [0u8; 16];
    OsRng.try_fill_bytes(&mut bytes).ok()?;
    Some(
        Builder::from_random_bytes(bytes)
            .into_uuid()
            .simple()
            .to_string(),
    )
}

macro_rules! redemption_select {
    ($suffix:literal) => {
        concat!(
            "SELECT CAST(id AS BIGINT) AS id, CAST(user_id AS BIGINT) AS user_id, ",
            "\"key\", CAST(status AS BIGINT) AS status, name, ",
            "CAST(quota AS BIGINT) AS quota, ",
            "CAST(redeemed_time AS BIGINT) AS redeemed_time, ",
            "CAST(created_time AS BIGINT) AS created_time, ",
            "CAST(used_user_id AS BIGINT) AS used_user_id, ",
            "CAST(expired_time AS BIGINT) AS expired_time",
            $suffix
        )
    };
}

const ALL_COUNT_SQL: &str = "SELECT COUNT(*) FROM redemptions WHERE deleted_at IS NULL";
const ALL_LIST_SQL: &str = redemption_select!(
    " FROM redemptions WHERE deleted_at IS NULL ORDER BY id DESC LIMIT $1 OFFSET $2"
);
const BY_ID_SQL: &str = redemption_select!(" FROM redemptions WHERE id=$1 AND deleted_at IS NULL");
const INSERT_SQL: &str = concat!(
    "INSERT INTO redemptions (user_id, \"key\", name, quota, redeemed_time, ",
    "created_time, used_user_id, expired_time) VALUES ",
    "($1,$2,$3,COALESCE(NULLIF($4,0),100),0,0,0,$5) RETURNING CAST(id AS BIGINT)"
);
const UPDATE_SQL: &str = concat!(
    "UPDATE redemptions SET name=$1, status=$2, quota=$3, redeemed_time=$4, ",
    "expired_time=$5 WHERE id=$6 AND deleted_at IS NULL"
);
const SOFT_DELETE_SQL: &str =
    "UPDATE redemptions SET deleted_at=CURRENT_TIMESTAMP WHERE id=$1 AND deleted_at IS NULL";
/// Go `DeleteInvalidRedemptions`：`status IN (used, disabled)` 或
/// `status = enabled 且已过 expired_time`；软删除，返回命中行数。
const PURGE_INVALID_SQL: &str = concat!(
    "UPDATE redemptions SET deleted_at=CURRENT_TIMESTAMP WHERE deleted_at IS NULL AND ",
    "(status IN (3, 2) OR (status = 1 AND expired_time != 0 AND expired_time < $1))"
);

macro_rules! decode_redemption {
    ($row:expr) => {{
        let row = $row;
        RedemptionRecord {
            id: row.try_get::<Option<i64>, _>("id")?.unwrap_or_default(),
            user_id: row
                .try_get::<Option<i64>, _>("user_id")?
                .unwrap_or_default(),
            key: row.try_get::<Option<String>, _>("key")?.unwrap_or_default(),
            status: row.try_get::<Option<i64>, _>("status")?.unwrap_or_default(),
            name: row
                .try_get::<Option<String>, _>("name")?
                .unwrap_or_default(),
            quota: row.try_get::<Option<i64>, _>("quota")?.unwrap_or_default(),
            redeemed_time: row
                .try_get::<Option<i64>, _>("redeemed_time")?
                .unwrap_or_default(),
            created_time: row
                .try_get::<Option<i64>, _>("created_time")?
                .unwrap_or_default(),
            used_user_id: row
                .try_get::<Option<i64>, _>("used_user_id")?
                .unwrap_or_default(),
            expired_time: row
                .try_get::<Option<i64>, _>("expired_time")?
                .unwrap_or_default(),
        }
    }};
}

/// 动态筛选的绑定值：Go `QueryRedemptions` 的 keyword/status 条件在运行时
/// 装配，参数个数不定，故用带类型的绑定枚举在两条查询间复用。
enum FilterBind {
    Int(i64),
    Text(String),
}

/// 装配 `QueryRedemptions` 的 WHERE 条件与参数：
/// - keyword 非空时，若能解析为 int 则 `id = ? OR name LIKE keyword+'%'`，
///   否则只 `name LIKE keyword+'%'`（LIKE 不转义，与 Go 一致）。
/// - status 命中四档之一时追加对应条件；`expired`/`enabled` 需要 `now`。
fn filter_conditions(
    keyword: &str,
    status: RedemptionStatusFilter,
    now: i64,
) -> (Vec<String>, Vec<FilterBind>) {
    let mut conditions = Vec::new();
    let mut binds = Vec::new();
    if !keyword.is_empty() {
        let index = binds.len() + 1;
        match keyword.parse::<i64>() {
            Ok(id) => {
                conditions.push(format!("(id = ${index} OR name LIKE ${})", index + 1));
                binds.push(FilterBind::Int(id));
            }
            Err(_) => {
                conditions.push(format!("name LIKE ${index}"));
            }
        }
        binds.push(FilterBind::Text(format!("{keyword}%")));
    }
    match status {
        RedemptionStatusFilter::Enabled => {
            let index = binds.len() + 1;
            conditions.push(format!(
                "status = {} AND (expired_time = 0 OR expired_time >= ${index})",
                REDEMPTION_STATUS_ENABLED
            ));
            binds.push(FilterBind::Int(now));
        }
        RedemptionStatusFilter::Expired => {
            let index = binds.len() + 1;
            conditions.push(format!(
                "status = {} AND expired_time != 0 AND expired_time < ${index}",
                REDEMPTION_STATUS_ENABLED
            ));
            binds.push(FilterBind::Int(now));
        }
        RedemptionStatusFilter::Disabled => {
            conditions.push(format!("status = {}", REDEMPTION_STATUS_DISABLED));
        }
        RedemptionStatusFilter::Used => {
            conditions.push(format!("status = {}", REDEMPTION_STATUS_USED));
        }
        RedemptionStatusFilter::None => {}
    }
    (conditions, binds)
}

/// 把条件拼成 `WHERE deleted_at IS NULL [AND ...]` 的 SQL 片段。
fn where_clause(conditions: &[String]) -> String {
    if conditions.is_empty() {
        " WHERE deleted_at IS NULL".to_owned()
    } else {
        format!(" WHERE deleted_at IS NULL AND {}", conditions.join(" AND "))
    }
}

/// 绑定动态参数并执行 count + list（事务内，与 Go 的 Begin/Commit 同构）。
/// `Executor` 不跨数据库种类，故用宏在每个后端上实例化一次。
///
/// 条件片段都是内部硬编码 SQL 文本加 `$N` 占位符，keyword/status 只经绑定
/// 参数进库，SQL 文本不含用户输入，故用 `AssertSqlSafe` 显式断言。
macro_rules! filtered_query {
    ($transaction:expr, $count_sql:expr, $list_sql:expr, $binds:expr, $limit:expr, $offset:expr) => {{
        let mut count = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe($count_sql));
        for bind in &$binds {
            match bind {
                FilterBind::Int(value) => count = count.bind(*value),
                FilterBind::Text(value) => count = count.bind(value.as_str()),
            }
        }
        let total = count.fetch_one(&mut *$transaction).await?;
        let mut list = sqlx::query(sqlx::AssertSqlSafe($list_sql));
        for bind in &$binds {
            match bind {
                FilterBind::Int(value) => list = list.bind(*value),
                FilterBind::Text(value) => list = list.bind(value.as_str()),
            }
        }
        let list = list.bind($limit).bind($offset);
        let rows = list.fetch_all(&mut *$transaction).await?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            records.push(decode_redemption!(row));
        }
        Ok::<(Vec<RedemptionRecord>, i64), sqlx::Error>((records, total))
    }};
}

pub struct RedemptionRepository {
    db: Database,
}

impl RedemptionRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Go `QueryAllRedemptions`：总数 + 按 id 倒序分页，单事务。
    pub async fn list_all(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<RedemptionRecord>, i64), sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let count = sqlx::query_scalar::<_, i64>(ALL_COUNT_SQL);
                let total = count.fetch_one(&mut *transaction).await?;
                let mut list = sqlx::query(ALL_LIST_SQL);
                list = list.bind(limit).bind(offset);
                let rows = list.fetch_all(&mut *transaction).await?;
                let mut records = Vec::with_capacity(rows.len());
                for row in rows {
                    records.push(decode_redemption!(row));
                }
                transaction.commit().await?;
                Ok((records, total))
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let count = sqlx::query_scalar::<_, i64>(ALL_COUNT_SQL);
                let total = count.fetch_one(&mut *transaction).await?;
                let mut list = sqlx::query(ALL_LIST_SQL);
                list = list.bind(limit).bind(offset);
                let rows = list.fetch_all(&mut *transaction).await?;
                let mut records = Vec::with_capacity(rows.len());
                for row in rows {
                    records.push(decode_redemption!(row));
                }
                transaction.commit().await?;
                Ok((records, total))
            }
        }
    }

    /// Go `QueryRedemptions`：keyword/status 过滤 + 总数 + 按 id 倒序分页，
    /// 单事务。过滤条件与参数由 [`filter_conditions`] 装配。
    pub async fn search(
        &self,
        keyword: &str,
        status: RedemptionStatusFilter,
        offset: i64,
        limit: i64,
        now: i64,
    ) -> Result<(Vec<RedemptionRecord>, i64), sqlx::Error> {
        let (conditions, binds) = filter_conditions(keyword, status, now);
        let where_sql = where_clause(&conditions);
        let count_sql = format!("SELECT COUNT(*) FROM redemptions{where_sql}");
        let list_sql = format!(
            "{} FROM redemptions{where_sql} ORDER BY id DESC LIMIT ${} OFFSET ${}",
            redemption_select!(""),
            binds.len() + 1,
            binds.len() + 2
        );
        match &self.db {
            Database::Sqlite(pool) => {
                let mut transaction = pool.begin().await?;
                let result = filtered_query!(
                    transaction,
                    count_sql.as_str(),
                    list_sql.as_str(),
                    binds,
                    limit,
                    offset
                );
                transaction.commit().await?;
                result
            }
            Database::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                let result = filtered_query!(
                    transaction,
                    count_sql.as_str(),
                    list_sql.as_str(),
                    binds,
                    limit,
                    offset
                );
                transaction.commit().await?;
                result
            }
        }
    }

    /// Go `GetRedemptionById`；`id = 0` 与软删除行都返回 `None`
    /// （调用方先判 id、再判未找到）。
    pub async fn by_id(&self, id: i64) -> Result<Option<RedemptionRecord>, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                match sqlx::query(BY_ID_SQL).bind(id).fetch_optional(pool).await? {
                    Some(row) => Ok(Some(decode_redemption!(row))),
                    None => Ok(None),
                }
            }
            Database::Postgres(pool) => {
                match sqlx::query(BY_ID_SQL).bind(id).fetch_optional(pool).await? {
                    Some(row) => Ok(Some(decode_redemption!(row))),
                    None => Ok(None),
                }
            }
        }
    }

    /// Go `Redemption.Insert`；返回新生成的 id。
    pub async fn insert(&self, redemption: &NewRedemption) -> Result<i64, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar(INSERT_SQL)
                    .bind(redemption.user_id)
                    .bind(&redemption.key)
                    .bind(&redemption.name)
                    .bind(redemption.quota)
                    .bind(redemption.expired_time)
                    .fetch_one(pool)
                    .await
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar(INSERT_SQL)
                    .bind(redemption.user_id)
                    .bind(&redemption.key)
                    .bind(&redemption.name)
                    .bind(redemption.quota)
                    .bind(redemption.expired_time)
                    .fetch_one(pool)
                    .await
            }
        }
    }

    /// Go `Redemption.Update`（GORM `Select` 五列）；零行匹配不报错，
    /// 与 GORM 的 `Updates` 行为一致。
    pub async fn update(&self, id: i64, update: &RedemptionUpdate) -> Result<(), sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(UPDATE_SQL)
                    .bind(&update.name)
                    .bind(update.status)
                    .bind(update.quota)
                    .bind(update.redeemed_time)
                    .bind(update.expired_time)
                    .bind(id)
                    .execute(pool)
                    .await?;
            }
            Database::Postgres(pool) => {
                sqlx::query(UPDATE_SQL)
                    .bind(&update.name)
                    .bind(update.status)
                    .bind(update.quota)
                    .bind(update.redeemed_time)
                    .bind(update.expired_time)
                    .bind(id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    /// Go `Redemption.Delete`：软删除置 `deleted_at`。
    pub async fn soft_delete(&self, id: i64) -> Result<(), sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query(SOFT_DELETE_SQL).bind(id).execute(pool).await?;
            }
            Database::Postgres(pool) => {
                sqlx::query(SOFT_DELETE_SQL).bind(id).execute(pool).await?;
            }
        }
        Ok(())
    }

    /// Go `DeleteInvalidRedemptions`：软删除 used/disabled 与已过期的 enabled
    /// 码，返回命中行数（Go 的 `RowsAffected`）。
    pub async fn delete_invalid(&self, now: i64) -> Result<i64, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => sqlx::query(PURGE_INVALID_SQL)
                .bind(now)
                .execute(pool)
                .await
                .map(|result| result.rows_affected() as i64),
            Database::Postgres(pool) => sqlx::query(PURGE_INVALID_SQL)
                .bind(now)
                .execute(pool)
                .await
                .map(|result| result.rows_affected() as i64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_matches_go_getuuid_shape() {
        let key = generate_redemption_key().expect("osrng");
        assert_eq!(key.len(), 32, "uuid sans dashes is 32 hex chars");
        assert!(
            key.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "lowercase hex only"
        );
        // UUIDv4 的版本位：第 13 个字符固定为 4。
        assert_eq!(key.as_bytes()[12], b'4', "version nibble must be 4");
        // 两次生成不重复，确认随机性。
        let other = generate_redemption_key().expect("osrng");
        assert_ne!(key, other);
    }

    #[test]
    fn status_filter_maps_only_go_switch_values() {
        assert_eq!(
            RedemptionStatusFilter::from_query(""),
            RedemptionStatusFilter::None
        );
        assert_eq!(
            RedemptionStatusFilter::from_query("expired"),
            RedemptionStatusFilter::Expired
        );
        assert_eq!(
            RedemptionStatusFilter::from_query("1"),
            RedemptionStatusFilter::Enabled
        );
        assert_eq!(
            RedemptionStatusFilter::from_query("2"),
            RedemptionStatusFilter::Disabled
        );
        assert_eq!(
            RedemptionStatusFilter::from_query("3"),
            RedemptionStatusFilter::Used
        );
        // 未登记的值与缺省一样不过滤。
        assert_eq!(
            RedemptionStatusFilter::from_query("9"),
            RedemptionStatusFilter::None
        );
    }

    #[test]
    fn keyword_numeric_branch_binds_id_and_like() {
        let (conditions, binds) = filter_conditions("12", RedemptionStatusFilter::None, 1_000);
        assert_eq!(conditions.len(), 1);
        assert_eq!(conditions[0], "(id = $1 OR name LIKE $2)");
        assert_eq!(binds.len(), 2);
        match &binds[1] {
            FilterBind::Text(value) => assert_eq!(value, "12%"),
            FilterBind::Int(_) => panic!("like pattern must be text"),
        }
    }

    #[test]
    fn keyword_non_numeric_binds_a_single_like() {
        let (conditions, binds) = filter_conditions("gift", RedemptionStatusFilter::None, 1_000);
        assert_eq!(conditions, vec!["name LIKE $1".to_owned()]);
        assert_eq!(binds.len(), 1);
        match &binds[0] {
            FilterBind::Text(value) => assert_eq!(value, "gift%"),
            FilterBind::Int(_) => panic!("like pattern must be text"),
        }
    }

    #[test]
    fn placeholder_numbering_composes_across_filters() {
        // keyword 用掉 $1/$2，status 的 enabled 从 $3 接着编号。
        let (conditions, binds) = filter_conditions("12", RedemptionStatusFilter::Enabled, 900);
        assert_eq!(
            conditions,
            vec![
                "(id = $1 OR name LIKE $2)".to_owned(),
                "status = 1 AND (expired_time = 0 OR expired_time >= $3)".to_owned()
            ]
        );
        assert_eq!(binds.len(), 3);
        match &binds[2] {
            FilterBind::Int(now) => assert_eq!(*now, 900),
            FilterBind::Text(_) => panic!("now must be int"),
        }
    }

    #[test]
    fn where_clause_keeps_deleted_at_scope() {
        let empty = where_clause(&[]);
        assert_eq!(empty, " WHERE deleted_at IS NULL");
        let one = where_clause(&["status = 2".to_owned()]);
        assert_eq!(one, " WHERE deleted_at IS NULL AND status = 2");
    }

    /// 直接在仓储层执行一次 search 的装配 SQL（最小夹具）：回归守卫，
    /// 确保动态拼出的 list 语句保留 `FROM redemptions`（漏掉 FROM 会让
    /// 两条后端都报 `no such column: id`）。
    const SQLITE_REDEMPTIONS_DDL: &str = r#"CREATE TABLE redemptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        "key" CHAR(32) NOT NULL UNIQUE,
        status INTEGER NOT NULL DEFAULT 1,
        name TEXT NOT NULL DEFAULT '',
        quota INTEGER NOT NULL DEFAULT 100,
        redeemed_time BIGINT NOT NULL DEFAULT 0,
        created_time BIGINT NOT NULL DEFAULT 0,
        used_user_id INTEGER NOT NULL DEFAULT 0,
        expired_time BIGINT NOT NULL DEFAULT 0,
        deleted_at TIMESTAMP
    )"#;

    #[tokio::test]
    async fn sqlite_search_runs_the_assembled_queries() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory SQLite fixture");
        sqlx::query(SQLITE_REDEMPTIONS_DDL)
            .execute(&pool)
            .await
            .expect("fixture schema");
        for row in [
            (10i64, 1i64, "kk10", "alpha", 1i64, 100i64),
            (20, 1, "kk20", "apple", 2, 100),
            (30, 1, "kk30", "beta", 3, 100),
        ] {
            sqlx::query(
                r#"INSERT INTO redemptions (id,user_id,"key",status,name,quota)
                   VALUES (?,?,?,?,?,?)"#,
            )
            .bind(row.0)
            .bind(row.1)
            .bind(row.2)
            .bind(row.4)
            .bind(row.3)
            .bind(row.5)
            .execute(&pool)
            .await
            .expect("seed row");
        }
        let repository = RedemptionRepository::new(Database::Sqlite(pool));
        // `ap%` 只命中 apple（alpha 以 "al" 开头）。
        let (records, total) = repository
            .search("ap", RedemptionStatusFilter::None, 0, 10, 1_000_000)
            .await
            .expect("search must succeed against the fixture");
        assert_eq!(total, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "apple");
        // 数字 keyword 走 `id = ? OR name LIKE ?` 分支（id=30 为 used）。
        let (records, total) = repository
            .search("30", RedemptionStatusFilter::Used, 0, 10, 1_000_000)
            .await
            .expect("numeric keyword search must succeed");
        assert_eq!(total, 1);
        assert_eq!(records[0].id, 30);
    }
}
