use std::collections::BTreeMap;

use newapi_catalog::group_settings::GroupSettings;
use newapi_storage::Database;
use sqlx::{
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

async fn execute(db: &Database, sql: &'static str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(sql).execute(pool).await.unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(sql).execute(pool).await.unwrap();
        }
    }
}

async fn insert(db: &Database, key: &str, value: Option<&str>) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO options (\"key\", \"value\") VALUES (?, ?)")
                .bind(key)
                .bind(value)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO options (\"key\", \"value\") VALUES ($1, $2)")
                .bind(key)
                .bind(value)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

async fn update(db: &Database, key: &str, value: &str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("UPDATE options SET \"value\" = ? WHERE \"key\" = ?")
                .bind(value)
                .bind(key)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("UPDATE options SET \"value\" = $1 WHERE \"key\" = $2")
                .bind(value)
                .bind(key)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

fn go_default_usable_groups() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("default".to_owned(), "默认分组".to_owned()),
        ("vip".to_owned(), "vip分组".to_owned()),
    ])
}

// Runs unchanged against both real SQLx backends, including failure paths.
async fn contract(db: &Database) {
    let default = GroupSettings::default();

    // Go seeds GroupRatio/GroupGroupRatio empty and UserUsableGroups with the
    // two default groups before any persisted row is applied.
    assert!(default.group_ratio.is_empty());
    assert!(default.group_group_ratio.is_empty());
    assert_eq!(default.user_usable_groups, go_default_usable_groups());

    // A missing options table is an error, not a silent set of defaults.
    assert!(GroupSettings::load(db, &default).await.is_err());

    execute(
        db,
        "CREATE TEMP TABLE options (\"key\" TEXT PRIMARY KEY, \"value\" TEXT)",
    )
    .await;

    // No rows at all still yields the Go defaults.
    let empty = GroupSettings::load(db, &default).await.unwrap();
    assert_eq!(empty, default);

    insert(
        db,
        "GroupRatio",
        Some(r#"{"default":1,"vip":2.5,"free":0}"#),
    )
    .await;
    insert(
        db,
        "UserUsableGroups",
        Some(r#"{"default":"默认分组","vip":"vip分组","auto":"自动分组"}"#),
    )
    .await;
    insert(
        db,
        "GroupGroupRatio",
        Some(r#"{"vip":{"default":0.4,"free":0.2}}"#),
    )
    .await;

    let loaded = GroupSettings::load(db, &default).await.unwrap();
    assert_eq!(
        loaded.group_ratio,
        BTreeMap::from([
            ("default".to_owned(), 1.0),
            ("vip".to_owned(), 2.5),
            ("free".to_owned(), 0.0),
        ])
    );
    assert_eq!(
        loaded.user_usable_groups,
        BTreeMap::from([
            ("default".to_owned(), "默认分组".to_owned()),
            ("vip".to_owned(), "vip分组".to_owned()),
            ("auto".to_owned(), "自动分组".to_owned()),
        ])
    );
    assert_eq!(
        loaded.group_group_ratio,
        BTreeMap::from([(
            "vip".to_owned(),
            BTreeMap::from([("default".to_owned(), 0.4), ("free".to_owned(), 0.2),])
        )])
    );

    // Invalid JSON or a wrong shape falls back to the Go default for that key,
    // not the previous value and not an error.
    for value in ["", "not json", "[]", r#"{"default":"1"}"#] {
        update(db, "GroupRatio", value).await;
        let fallback = GroupSettings::load(db, &loaded).await.unwrap();
        assert!(fallback.group_ratio.is_empty(), "value={value:?}");
        // Untouched keys keep their configured values.
        assert_eq!(fallback.user_usable_groups, loaded.user_usable_groups);
        assert_eq!(fallback.group_group_ratio, loaded.group_group_ratio);
    }
    for value in ["", "not json", "[]", r#"{"default":1}"#] {
        update(db, "UserUsableGroups", value).await;
        let fallback = GroupSettings::load(db, &loaded).await.unwrap();
        assert_eq!(
            fallback.user_usable_groups,
            go_default_usable_groups(),
            "value={value:?}"
        );
    }
    for value in ["", "not json", "[]", r#"{"vip":1}"#] {
        update(db, "GroupGroupRatio", value).await;
        let fallback = GroupSettings::load(db, &loaded).await.unwrap();
        assert!(fallback.group_group_ratio.is_empty(), "value={value:?}");
    }

    // Restore valid values, then prove a missing row retains the previous
    // snapshot value (the hot-reload contract).
    update(db, "GroupRatio", r#"{"default":1}"#).await;
    update(db, "UserUsableGroups", r#"{"default":"Default"}"#).await;
    update(db, "GroupGroupRatio", r#"{"default":{"vip":3}}"#).await;
    let before_delete = GroupSettings::load(db, &default).await.unwrap();
    assert_eq!(before_delete.group_ratio.len(), 1);
    execute(db, "DELETE FROM options WHERE \"key\" = 'GroupRatio'").await;
    execute(db, "DELETE FROM options WHERE \"key\" = 'UserUsableGroups'").await;
    execute(db, "DELETE FROM options WHERE \"key\" = 'GroupGroupRatio'").await;
    let kept = GroupSettings::load(db, &before_delete).await.unwrap();
    assert_eq!(kept, before_delete);
    let fresh = GroupSettings::load(db, &default).await.unwrap();
    assert_eq!(fresh, default);

    // SQL NULL in the value column is a decode error and does not mutate the
    // caller's previous snapshot.
    insert(db, "GroupRatio", Some(r#"{"default":1}"#)).await;
    let stable = GroupSettings::load(db, &default).await.unwrap();
    execute(
        db,
        "UPDATE options SET \"value\" = NULL WHERE \"key\" = 'GroupRatio'",
    )
    .await;
    assert!(GroupSettings::load(db, &stable).await.is_err());
    assert_eq!(stable.group_ratio.len(), 1);

    // A dropped table or a closed pool surfaces an error rather than stale data.
    execute(db, "DROP TABLE options").await;
    assert!(GroupSettings::load(db, &stable).await.is_err());
    db.close().await;
    assert!(GroupSettings::load(db, &stable).await.is_err());
}

#[tokio::test]
async fn sqlite_group_settings_contract() {
    // One in-memory connection owns the temporary table for the whole contract.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(SqliteConnectOptions::new().in_memory(true))
        .await
        .unwrap();
    contract(&Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_group_settings_contract() {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return;
    };
    // Exactly one persistent connection owns its temporary table. Search only
    // pg_temp so no existing public.options is read or modified by fixtures.
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET search_path TO pg_temp")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect(&dsn)
        .await
        .unwrap_or_else(|_| panic!("PostgreSQL test connection failed"));
    contract(&Database::Postgres(pool)).await;
}
