//! Group option snapshot.
//!
//! Mirrors the Go runtime state read by `handler.GetUserGroups` and
//! `identity.GetUserModels`:
//!
//! - `GroupRatio` -> `ratio_setting.GetGroupRatioCopy()`
//! - `UserUsableGroups` -> `channel.GetUserUsableGroups`
//! - `GroupGroupRatio` -> `ratio_setting.GetGroupGroupRatio`, the first half of
//!   `channel.GetUserGroupRatio`
//! - `GroupSpecialUsableGroup` ->
//!   `ratio_setting.GetGroupRatioSetting().GroupSpecialUsableGroup`, the
//!   per-user-group overlay applied by `channel.GetUserUsableGroups`
//! - `AutoGroups` -> `channel.GetAutoGroups()`, the ordered list behind
//!   `channel.GetUserAutoGroup`
//!
//! Go keeps these maps in memory and refreshes them from the `options` table
//! at startup, on every option write, and through the periodic `SyncOptions`
//! loop; the Rust equivalent loads this snapshot in `AppState::reload`
//! (startup + reload worker), which is what the handlers read.
//!
//! Defaults mirror the values seeded before any persisted option row is
//! applied (Go `catalog/resolve_group.go` and
//! `catalog/configure_ratio/configure_group_ratio.go`): `GroupRatio`/
//! `GroupGroupRatio`/`GroupSpecialUsableGroup` start empty,
//! `UserUsableGroups` starts as `{"default":"默认分组","vip":"vip分组"}`,
//! and `AutoGroups` starts as `["default"]`.

use std::collections::{BTreeMap, BTreeSet};

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
    /// Go `GroupSpecialUsableGroup`（选项键
    /// `group_ratio_setting.group_special_usable_group`）：用户组 ->
    /// 特殊分组覆盖。覆盖键以 `-:` 前缀移除分组、以 `+:` 前缀或无前缀加入分组。
    pub group_special_usable_group: BTreeMap<String, BTreeMap<String, String>>,
    /// Go `AutoGroups`（选项键 `AutoGroups`）：自动分组的有序列表，
    /// `user_auto_group` 按此顺序过滤可选项。Go 种子值为 `["default"]`。
    pub auto_groups: Vec<String>,
}

impl Default for GroupSettings {
    fn default() -> Self {
        Self {
            // Go `groupRatioMap` starts empty and has no hardcoded fallbacks.
            group_ratio: BTreeMap::new(),
            user_usable_groups: default_user_usable_groups(),
            // Go `groupGroupRatioMap` starts empty.
            group_group_ratio: BTreeMap::new(),
            // Go `defaultGroupSpecialUsableGroup` is an empty map.
            group_special_usable_group: BTreeMap::new(),
            // Go package-level `autoGroups = []string{"default"}`.
            auto_groups: default_auto_groups(),
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
    /// non-empty user group, apply the `GroupSpecialUsableGroup` overlay and
    /// ensure that group itself is listed. Go appends it with the literal
    /// description `"用户分组"` when the configured map does not contain it.
    ///
    /// 覆盖语义（Go `resolve_group.go`）：用户组存在特殊配置时，`-:x`
    /// 移除分组 `x`；`+:x` 或裸键 `x` 加入分组并设置描述。Go 遍历 map
    /// 的顺序随机，冲突键的最终值不确定；Rust 按 BTreeMap 键序应用，
    /// 结果确定但同样不做冲突承诺。
    pub fn user_usable_groups(&self, user_group: &str) -> BTreeMap<String, String> {
        let mut groups = self.user_usable_groups.clone();
        if !user_group.is_empty() {
            if let Some(special) = self.group_special_usable_group.get(user_group) {
                for (special_group, desc) in special {
                    if let Some(remove) = special_group.strip_prefix("-:") {
                        groups.remove(remove);
                    } else {
                        let add = special_group.strip_prefix("+:").unwrap_or(special_group);
                        groups.insert(add.to_owned(), desc.clone());
                    }
                }
            }
            groups
                .entry(user_group.to_owned())
                .or_insert_with(|| USER_GROUP_DESCRIPTION.to_owned());
        }
        groups
    }

    /// Go `channel.IsUserSelectableGroup`: empty and `auto` are never
    /// selectable, and a group must be both usable for this user group and
    /// present in `GroupRatio`.
    fn is_user_selectable_group(&self, usable: &BTreeMap<String, String>, group: &str) -> bool {
        !group.is_empty()
            && group != "auto"
            && usable.contains_key(group)
            && self.group_ratio.contains_key(group)
    }

    /// Go `channel.GetUserAutoGroup`: the ordered `AutoGroups` list filtered
    /// down to selectable groups for the user group, deduplicated, preserving
    /// the configured order.
    pub fn user_auto_group(&self, user_group: &str) -> Vec<String> {
        let usable = self.user_usable_groups(user_group);
        let mut seen = BTreeSet::new();
        self.auto_groups
            .iter()
            .filter(|group| {
                self.is_user_selectable_group(&usable, group) && seen.insert((*group).clone())
            })
            .cloned()
            .collect()
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

fn default_auto_groups() -> Vec<String> {
    // Go `catalog/resolve_group.go` package-level `autoGroups`.
    vec!["default".to_owned()]
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
            group_special_usable_group: BTreeMap::new(),
            auto_groups: vec!["default".to_owned()],
        }
    }

    #[test]
    fn defaults_match_go_seed_values() {
        let defaults = GroupSettings::default();
        assert!(defaults.group_ratio.is_empty());
        assert!(defaults.group_group_ratio.is_empty());
        assert!(defaults.group_special_usable_group.is_empty());
        assert_eq!(defaults.auto_groups, vec!["default".to_owned()]);
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
    fn special_overlay_adds_and_removes_groups() {
        // Go `TestGetUserModelsExpandsAutoGroupsInConfiguredOrder` configures
        // the same overlay: `+:vip` adds, `-:unavailable` removes, and the
        // user group itself stays.
        let mut settings = settings();
        settings
            .user_usable_groups
            .insert("unavailable".to_owned(), "不可用分组".to_owned());
        settings.group_special_usable_group.insert(
            "default".to_owned(),
            BTreeMap::from([
                ("+:vip".to_owned(), "VIP 分组".to_owned()),
                ("-:unavailable".to_owned(), String::new()),
            ]),
        );
        let usable = settings.user_usable_groups("default");
        assert_eq!(usable.get("vip").map(String::as_str), Some("VIP 分组"));
        assert!(!usable.contains_key("unavailable"));
        assert!(usable.contains_key("default"));
    }

    #[test]
    fn special_overlay_ignores_other_user_groups_and_empty() {
        let mut settings = settings();
        settings.group_special_usable_group.insert(
            "vip".to_owned(),
            BTreeMap::from([("+:extra".to_owned(), "额外".to_owned())]),
        );
        // A different user group does not get the overlay.
        assert!(!settings.user_usable_groups("default").contains_key("extra"));
        // Neither does an empty user group: Go guards both the overlay and the
        // user-group append on `userGroup != ""`.
        assert!(!settings.user_usable_groups("").contains_key("extra"));
        let vip = settings.user_usable_groups("vip");
        assert_eq!(vip.get("extra").map(String::as_str), Some("额外"));
    }

    #[test]
    fn auto_group_keeps_configured_order_of_selectable_groups() {
        // Mirrors the Go auto test: usable {auto, default, vip(+overlay)},
        // AutoGroups order [vip, default, unavailable] keeps [vip, default].
        let mut settings = settings();
        settings
            .user_usable_groups
            .insert("unavailable".to_owned(), "不可用分组".to_owned());
        settings.group_ratio.insert("unavailable".to_owned(), 1.0);
        settings.group_special_usable_group.insert(
            "default".to_owned(),
            BTreeMap::from([
                ("+:vip".to_owned(), "VIP 分组".to_owned()),
                ("-:unavailable".to_owned(), String::new()),
            ]),
        );
        settings.auto_groups = vec![
            "vip".to_owned(),
            "default".to_owned(),
            "unavailable".to_owned(),
        ];
        assert_eq!(
            settings.user_auto_group("default"),
            vec!["vip".to_owned(), "default".to_owned()]
        );
    }

    #[test]
    fn auto_group_excludes_unusable_and_unpriced_groups() {
        let mut settings = settings();
        // `auto` is usable but never selectable; `free` is usable and in
        // AutoGroups but missing from GroupRatio; `gone` is not usable.
        settings.auto_groups = vec![
            "auto".to_owned(),
            "free".to_owned(),
            "default".to_owned(),
            "gone".to_owned(),
        ];
        settings
            .user_usable_groups
            .insert("free".to_owned(), "免费分组".to_owned());
        assert_eq!(
            settings.user_auto_group("default"),
            vec!["default".to_owned()]
        );
        // Without any auto option configured the default list is ["default"].
        let defaults = GroupSettings::default();
        assert!(defaults.user_auto_group("default").is_empty());
    }

    #[test]
    fn auto_group_deduplicates_repeats() {
        let mut settings = settings();
        // Both `default` and `vip` are usable and in GroupRatio, so each
        // survives once despite the repeated `default` entry.
        settings.auto_groups = vec!["default".to_owned(), "vip".to_owned(), "default".to_owned()];
        assert_eq!(
            settings.user_auto_group("default"),
            vec!["default".to_owned(), "vip".to_owned()]
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
