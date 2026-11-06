//! Group option snapshot.
//!
//! Mirrors the Go runtime state read by `handler.GetUserGroups` and
//! `identity.GetUserModels`:
//!
//! - `GroupRatio` -> `ratio_setting.GetGroupRatioCopy()`
//! - `UserUsableGroups` -> `channel.GetUserUsableGroups`
//! - `GroupGroupRatio` -> `ratio_setting.GetGroupGroupRatio`, the first half of
//!   `channel.GetUserGroupRatio`
//!
//! Go keeps these maps in memory and refreshes them from the `options` table;
//! this snapshot is the typed equivalent. Until `AppState` owns a snapshot,
//! the group handlers load it per request (see `groups_http::load_settings`).
//!
//! Defaults mirror the values seeded before any persisted option row is
//! applied: `GroupRatio`/`GroupGroupRatio` start empty and `UserUsableGroups`
//! starts as `{"default":"默认分组","vip":"vip分组"}` (Go
//! `catalog/resolve_group.go`).
//!
//! Not yet loaded: `GroupSpecialUsableGroup`. Its Go default is empty, which
//! makes the overlay a no-op; groups configured there are therefore ignored
//! until a later slice adds it.

use std::collections::BTreeMap;

use newapi_storage::Database;

mod store;

/// Go hardcodes these two user-visible strings; they are not option values.
pub const AUTO_GROUP_RATIO: &str = "自动";
pub const USER_GROUP_DESCRIPTION: &str = "用户分组";

#[derive(Clone, Debug, PartialEq)]
pub struct GroupSettings {
    /// Go `GroupRatio`, keyed by group name.
    pub group_ratio: BTreeMap<String, f64>,
    /// Go `UserUsableGroups`, keyed by group name with the display description.
    pub user_usable_groups: BTreeMap<String, String>,
    /// Go `GroupGroupRatio`: user group -> using group -> ratio.
    pub group_group_ratio: BTreeMap<String, BTreeMap<String, f64>>,
}

impl Default for GroupSettings {
    fn default() -> Self {
        Self {
            // Go `groupRatioMap` starts empty and has no hardcoded fallbacks.
            group_ratio: BTreeMap::new(),
            user_usable_groups: default_user_usable_groups(),
            // Go `groupGroupRatioMap` starts empty.
            group_group_ratio: BTreeMap::new(),
        }
    }
}

impl GroupSettings {
    /// Fetch all group keys in one statement and return a complete replacement.
    /// Missing rows retain the corresponding `previous` value; SQL NULL is an
    /// error rather than a silent default. A row whose JSON is invalid falls
    /// back to the Go default for that key (see `store`).
    pub async fn load(db: &Database, previous: &Self) -> Result<Self, sqlx::Error> {
        store::load(db, previous).await
    }

    /// Go `channel.GetUserUsableGroups`: copy the configured map and, for a
    /// non-empty user group, ensure that group itself is listed. Go appends it
    /// with the literal description `"用户分组"` when the configured map does
    /// not contain it.
    ///
    /// The `GroupSpecialUsableGroup` overlay is not loaded yet; its default is
    /// empty, so omitting it is equivalent to the Go default configuration.
    pub fn user_usable_groups(&self, user_group: &str) -> BTreeMap<String, String> {
        let mut groups = self.user_usable_groups.clone();
        if !user_group.is_empty() {
            groups
                .entry(user_group.to_owned())
                .or_insert_with(|| USER_GROUP_DESCRIPTION.to_owned());
        }
        groups
    }

    /// Go `channel.GetUserGroupRatio`: the user-group-specific ratio when
    /// configured, otherwise the plain group ratio. Go `GetGroupRatio` falls
    /// back to `1` for an unknown group.
    pub fn user_group_ratio(&self, user_group: &str, group: &str) -> f64 {
        if let Some(ratio) = self
            .group_group_ratio
            .get(user_group)
            .and_then(|ratios| ratios.get(group))
        {
            return *ratio;
        }
        self.group_ratio.get(group).copied().unwrap_or(1.0)
    }
}

fn default_user_usable_groups() -> BTreeMap<String, String> {
    // Go `catalog/resolve_group.go` package-level `userUsableGroups`.
    BTreeMap::from([
        ("default".to_owned(), "默认分组".to_owned()),
        ("vip".to_owned(), "vip分组".to_owned()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> GroupSettings {
        GroupSettings {
            group_ratio: BTreeMap::from([("default".to_owned(), 1.0), ("vip".to_owned(), 2.0)]),
            user_usable_groups: BTreeMap::from([
                ("default".to_owned(), "默认分组".to_owned()),
                ("vip".to_owned(), "vip分组".to_owned()),
                ("auto".to_owned(), "自动分组".to_owned()),
            ]),
            group_group_ratio: BTreeMap::from([(
                "vip".to_owned(),
                BTreeMap::from([("default".to_owned(), 0.5)]),
            )]),
        }
    }

    #[test]
    fn defaults_match_go_seed_values() {
        let defaults = GroupSettings::default();
        assert!(defaults.group_ratio.is_empty());
        assert!(defaults.group_group_ratio.is_empty());
        assert_eq!(
            defaults.user_usable_groups,
            BTreeMap::from([
                ("default".to_owned(), "默认分组".to_owned()),
                ("vip".to_owned(), "vip分组".to_owned()),
            ])
        );
    }

    #[test]
    fn usable_groups_add_the_user_group_only_when_non_empty() {
        let settings = settings();
        assert!(!settings.user_usable_groups("").contains_key("custom"));
        let custom = settings.user_usable_groups("custom");
        assert_eq!(
            custom.get("custom").map(String::as_str),
            Some(USER_GROUP_DESCRIPTION)
        );
        // A configured group keeps its configured description.
        assert_eq!(
            settings
                .user_usable_groups("vip")
                .get("vip")
                .map(String::as_str),
            Some("vip分组")
        );
    }

    #[test]
    fn user_group_ratio_prefers_group_specific_configuration() {
        let settings = settings();
        assert_eq!(settings.user_group_ratio("vip", "default"), 0.5);
        assert_eq!(settings.user_group_ratio("default", "vip"), 2.0);
        // Unknown user group or unknown group falls back to the group ratio,
        // then to Go's `1`.
        assert_eq!(settings.user_group_ratio("default", "default"), 1.0);
        assert_eq!(settings.user_group_ratio("nobody", "missing"), 1.0);
    }
}
