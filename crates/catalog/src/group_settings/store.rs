use std::collections::BTreeMap;

use newapi_storage::Database;
use serde::Deserialize;
use sqlx::types::Json;

use super::GroupSettings;

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
            // Go `UpdateGroupRatioByJSONString` routes through
            // `types.LoadFromJsonString` (rw_map.go), which decodes a fresh
            // local map and returns early on failure without touching the
            // live map. An invalid row therefore keeps the previous snapshot
            // value (last-good); the empty seeded default applies only before
            // any row is ever applied.
            "GroupRatio" => {
                if let Some(ratio) = parse_json::<BTreeMap<String, f64>>(&value) {
                    next.group_ratio = ratio;
                }
            }
            // Go `UpdateUserUsableGroupsByJSONString` (resolve_group.go)
            // resets the map to empty before `Unmarshal`, so a row whose JSON
            // cannot be decoded leaves an empty map — not the two-entry
            // package seed, which only applies before any row is applied.
            "UserUsableGroups" => {
                next.user_usable_groups =
                    parse_json::<BTreeMap<String, String>>(&value).unwrap_or_default();
            }
            // Go `UpdateGroupGroupRatioByJSONString` uses the same
            // `LoadFromJsonString` last-good contract as `GroupRatio`, so an
            // invalid row keeps the previous snapshot value.
            "GroupGroupRatio" => {
                if let Some(ratio) = parse_json::<BTreeMap<String, BTreeMap<String, f64>>>(&value) {
                    next.group_group_ratio = ratio;
                }
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
