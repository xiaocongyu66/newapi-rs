use std::collections::BTreeMap;

use newapi_storage::Database;
use serde::Deserialize;
use sqlx::types::Json;

use super::{GroupSettings, default_user_usable_groups};

const KEYS: [&str; 5] = [
    "GroupRatio",
    "UserUsableGroups",
    "GroupGroupRatio",
    "group_ratio_setting.group_special_usable_group",
    "AutoGroups",
];

pub(super) async fn load(
    db: &Database,
    previous: &GroupSettings,
) -> Result<GroupSettings, sqlx::Error> {
    // Decode all rows before touching even the private replacement snapshot.
    let rows: Vec<(String, Option<String>)> = match db {
        Database::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN (?, ?, ?, ?, ?)",
            )
            .bind(KEYS[0])
            .bind(KEYS[1])
            .bind(KEYS[2])
            .bind(KEYS[3])
            .bind(KEYS[4])
            .fetch_all(pool)
            .await?
        }
        Database::Postgres(pool) => {
            sqlx::query_as(
                "SELECT \"key\", \"value\" FROM \"options\" \
                 WHERE \"key\" IN ($1, $2, $3, $4, $5)",
            )
            .bind(KEYS[0])
            .bind(KEYS[1])
            .bind(KEYS[2])
            .bind(KEYS[3])
            .bind(KEYS[4])
            .fetch_all(pool)
            .await?
        }
    };
    let rows = rows
        .into_iter()
        .map(|(key, value)| {
            value
                .map(|value| (key, value))
                .ok_or_else(|| sqlx::Error::ColumnDecode {
                    index: "value".to_owned(),
                    source: Box::new(sqlx::error::UnexpectedNullError),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut next = previous.clone();
    for (key, value) in rows {
        match key.as_str() {
            // Go `types.LoadFromJsonString` decodes a fresh map and only
            // replaces the runtime map on success. The seeded default is an
            // empty map, which is also the fallback required for invalid JSON.
            "GroupRatio" => {
                next.group_ratio = parse_json::<BTreeMap<String, f64>>(&value).unwrap_or_default();
            }
            // Go Unmarshal into `map[string]string`; the seeded default is the
            // two-entry map even when the persisted value cannot be decoded.
            "UserUsableGroups" => {
                next.user_usable_groups = parse_json::<BTreeMap<String, String>>(&value)
                    .unwrap_or_else(default_user_usable_groups);
            }
            // Go `map[string]map[string]float64`; the seeded default is empty.
            "GroupGroupRatio" => {
                next.group_group_ratio =
                    parse_json::<BTreeMap<String, BTreeMap<String, f64>>>(&value)
                        .unwrap_or_default();
            }
            // Go 分层配置 `group_ratio_setting.group_special_usable_group`：
            // `RWMap.UnmarshalJSON` 先重置再解码，失败时留下空 map，
            // 因此无效 JSON 的回退是空覆盖，而非保留旧值。
            "group_ratio_setting.group_special_usable_group" => {
                next.group_special_usable_group =
                    parse_json::<BTreeMap<String, BTreeMap<String, String>>>(&value)
                        .unwrap_or_default();
            }
            // Go `UpdateAutoGroupsByJsonString` 同样先重置再解码：失败时
            // autoGroups 为空列表，而不是种子默认值。
            "AutoGroups" => {
                next.auto_groups = parse_json::<Vec<String>>(&value).unwrap_or_default();
            }
            _ => {}
        }
    }
    Ok(next)
}

/// `sqlx` exposes `serde_json::from_str` through this small typed adapter, so
/// the catalog crate can parse the option strings without adding a direct
/// `serde_json` dependency. Invalid JSON (or a shape mismatch, such as a number
/// in `UserUsableGroups`) yields `None`.
fn parse_json<T>(value: &str) -> Option<T>
where
    T: for<'de> Deserialize<'de>,
{
    Json::<T>::decode_from_string(value)
        .ok()
        .map(|json| json.into_inner())
}
