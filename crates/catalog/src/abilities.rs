//! `abilities` 表读取：Go `catalog/store_ability.go`（`GetGroupEnabledModels`）
//! 与 `catalog/resolve_group_service.go`（`GetGroupsEnabledModels`）。
//!
//! `/api/user/models` 的模型清单完全由 `abilities` 决定（Go
//! `identity.groupModels` 解析器）：某分组下任意启用渠道提供的模型集合。
//! 渠道维护由后续 channel 切片负责，这里只提供分组→模型的只读投影。
//!
//! 与 Go 的差异：Go 的 `Distinct("model")` 不带 `ORDER BY`，组内顺序由
//! 数据库扫描决定且不限稳定；这里加 `ORDER BY model` 让单组顺序确定，
//! 组间顺序仍由调用方传入的分组列表决定（Go
//! `TestGetUserModelsExpandsAutoGroupsInConfiguredOrder` 只断言组间顺序）。

use newapi_storage::Database;

/// Go `GetGroupEnabledModels`：`abilities` 中该分组启用模型的去重列表。
///
/// 异常交由调用方处理：Go 吞掉数据库错误并返回空列表，但 Rust 侧约定
/// 不编造数据表缺失或连接故障下的“空模型”，由 HTTP 边界统一回 503。
pub async fn group_enabled_models(db: &Database, group: &str) -> Result<Vec<String>, sqlx::Error> {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar(
                "SELECT DISTINCT model FROM abilities \
                 WHERE \"group\" = ? AND enabled = ? ORDER BY model",
            )
            .bind(group)
            .bind(true)
            .fetch_all(pool)
            .await
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar(
                "SELECT DISTINCT model FROM abilities \
                 WHERE \"group\" = $1 AND enabled = $2 ORDER BY model",
            )
            .bind(group)
            .bind(true)
            .fetch_all(pool)
            .await
        }
    }
}

/// Go `GetGroupsEnabledModels`：按分组列表顺序合并各组启用模型，保留首次
/// 出现的模型（Go `seen` map 语义）。空列表产生空列表。
pub async fn groups_enabled_models(
    db: &Database,
    groups: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    let mut models = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for group in groups {
        for model in group_enabled_models(db, group).await? {
            if seen.insert(model.clone()) {
                models.push(model);
            }
        }
    }
    Ok(models)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup() -> Database {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            r#"CREATE TABLE abilities (
                "group" VARCHAR(64) NOT NULL,
                model VARCHAR(255) NOT NULL,
                channel_id INTEGER NOT NULL,
                enabled BOOLEAN NOT NULL,
                tag VARCHAR(255),
                PRIMARY KEY ("group", model, channel_id)
            )"#,
        )
        .execute(&pool)
        .await
        .unwrap();
        Database::Sqlite(pool)
    }

    async fn seed(db: &Database, group: &str, model: &str, channel: i64, enabled: bool) {
        sqlx::query(
            r#"INSERT INTO abilities ("group", model, channel_id, enabled)
               VALUES (?, ?, ?, ?)"#,
        )
        .bind(group)
        .bind(model)
        .bind(channel)
        .bind(enabled)
        .execute(match db {
            Database::Sqlite(pool) => pool,
            Database::Postgres(_) => unreachable!("sqlite-only unit test"),
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn distinct_enabled_models_for_one_group() {
        let db = setup().await;
        seed(&db, "default", "b-model", 1, true).await;
        seed(&db, "default", "a-model", 1, true).await;
        seed(&db, "default", "a-model", 2, true).await;
        seed(&db, "default", "disabled-model", 1, false).await;
        seed(&db, "vip", "vip-model", 1, true).await;
        // DISTINCT collapses the two channels, disabled rows drop out, and the
        // remaining names are ordered for a stable response.
        assert_eq!(
            group_enabled_models(&db, "default").await.unwrap(),
            vec!["a-model".to_owned(), "b-model".to_owned()]
        );
        assert_eq!(
            group_enabled_models(&db, "vip").await.unwrap(),
            vec!["vip-model".to_owned()]
        );
        assert!(
            group_enabled_models(&db, "unknown")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn union_preserves_group_order_and_first_occurrence() {
        let db = setup().await;
        seed(&db, "vip", "zz-vip", 1, true).await;
        seed(&db, "vip", "shared", 1, true).await;
        seed(&db, "default", "zz-default", 2, true).await;
        seed(&db, "default", "shared", 3, true).await;
        let groups = vec!["vip".to_owned(), "default".to_owned()];
        assert_eq!(
            groups_enabled_models(&db, &groups).await.unwrap(),
            vec![
                "shared".to_owned(),
                "zz-vip".to_owned(),
                "zz-default".to_owned()
            ]
        );
        assert!(groups_enabled_models(&db, &[]).await.unwrap().is_empty());
    }
}
