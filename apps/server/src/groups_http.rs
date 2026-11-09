//! `GET /api/user/groups`, `GET /api/user/self/groups`, and
//! `GET /api/user/models` HTTP adapters.
//!
//! Go references:
//! - `apps/api/internal/transport/handler/handle_group.go` (`GetUserGroups`)
//! - `apps/api/internal/identity/manage_users.go` (`GetUserModels`)
//! - `apps/api/internal/catalog/resolve_group.go`（可用分组覆盖与自动分组）
//! - `apps/api/internal/catalog/resolve_group_service.go`（`GetGroupsEnabledModels`）
//! - `apps/api/internal/transport/compose/register_api.go` (route wiring)
//!
//! `GET /api/user/groups` is registered without `UserAuth` in Go, so
//! `c.GetInt("id")` is 0 and the user group is empty. `GET
//! /api/user/self/groups` runs behind `UserAuth` and therefore sees the
//! authenticated user's group. Both routes share [`user_groups`] here; the
//! optional extension is present only when the router applied
//! [`crate::auth::user_auth`], which reproduces the Go difference.
//!
//! 组设置来自 `AppState::group_settings()` 快照（启动与 reload worker 装载，
//! 对齐 Go 的 `InitOptionMap` + `SyncOptions`）：数据库写入在下一次 reload
//! 前不可见，与 `notice` 等公共配置的快照语义一致。
//!
//! `GET /api/user/models` 的模型清单由 `abilities` 表决定（Go
//! `identity.groupModels` 解析器 → `GetGroupsEnabledModels`）：仅启用分组中
//! 的启用渠道模型，按用户组可用集合选择。

use axum::{
    Json,
    extract::{Extension, State},
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
};
use newapi_catalog::abilities::groups_enabled_models;
use newapi_catalog::group_settings::{AUTO_GROUP_RATIO, GroupSettings};
use serde_json::{Map, Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;

/// `GET /api/user/groups` and `GET /api/user/self/groups`.
///
/// Go `handler.GetUserGroups`: iterate the configured `GroupRatio` keys and
/// keep the ones in `GetUserUsableGroups(userGroup)`. `auto` is appended with
/// the literal string ratio `"自动"` when it is usable. Ratios are JSON numbers
/// except `auto`, which is a JSON string.
pub async fn user_groups(
    State(state): State<AppState>,
    authenticated: Option<Extension<AuthenticatedUser>>,
) -> Response {
    let user_group = authenticated
        .as_ref()
        .map(|Extension(user)| user.0.group.as_str())
        .unwrap_or("");
    Json(success_body(user_groups_body(
        &state.group_settings(),
        user_group,
    )))
    .into_response()
}

/// `GET /api/user/models`.
///
/// Go `identity.GetUserModels`: 读取认证用户的组，按 `group` 查询参数选择
/// 分组（`auto` 展开为有序自动分组列表），并从 `abilities` 表解析这些分组
/// 的启用模型。请求分组不在用户可用集合内时返回空列表，与 Go 一致。
pub async fn user_models(
    State(state): State<AppState>,
    Extension(authenticated): Extension<AuthenticatedUser>,
    uri: Uri,
) -> Response {
    let user_group = authenticated.0.group.as_str();
    let settings = state.group_settings();
    let groups = user_models_groups(&settings, user_group, requested_group(&uri).as_deref());
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match groups_enabled_models(&db, &groups).await {
        Ok(models) => Json(user_models_body(models)).into_response(),
        Err(error) => {
            tracing::warn!(
                event = "abilities_load_failed",
                category = crate::database_error_class(&error),
                "abilities load failed"
            );
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

/// Pure `GetUserModels` group selection, testable without routing or a
/// database.
///
/// Go switch: 无参数 → 全部可用分组（Go 遍历 map 顺序随机，Rust 按键序
/// 保证确定输出）；`auto` → 仅当 `auto` 可用时展开为自动分组列表；
/// 其它分组 → 仅当该分组可用时选中它。
pub fn user_models_groups(
    settings: &GroupSettings,
    user_group: &str,
    requested: Option<&str>,
) -> Vec<String> {
    let usable = settings.user_usable_groups(user_group);
    match requested {
        None | Some("") => usable.keys().cloned().collect(),
        Some("auto") => match usable.get("auto") {
            Some(_) => settings.user_auto_group(user_group),
            None => Vec::new(),
        },
        Some(group) => match usable.get(group) {
            Some(_) => vec![group.to_owned()],
            None => Vec::new(),
        },
    }
}

/// `c.Query("group")`: 缺省为 None；Go/axum 解码对齐（`+` 为空格，
/// `%XX` 按字节解码），与 `token_http::query_pairs` 同语义但只取 `group`。
fn requested_group(uri: &Uri) -> Option<String> {
    let query = uri.query()?;
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .find_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key == "group").then(|| percent_decode(value))
        })
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push(high * 16 + low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Pure `GetUserGroups` assembly, testable without routing or a database.
pub fn user_groups_body(settings: &GroupSettings, user_group: &str) -> Value {
    let usable = settings.user_usable_groups(user_group);
    let mut data = Map::new();
    for group in settings.group_ratio.keys() {
        if let Some(desc) = usable.get(group) {
            data.insert(
                group.clone(),
                json!({
                    "ratio": settings.user_group_ratio(user_group, group),
                    "desc": desc,
                }),
            );
        }
    }
    if let Some(desc) = usable.get("auto") {
        // Go hardcodes the auto ratio string; the description comes from the
        // configured usable-group map.
        data.insert(
            "auto".to_owned(),
            json!({ "ratio": AUTO_GROUP_RATIO, "desc": desc }),
        );
    }
    Value::Object(data)
}

/// Pure `GetUserModels` envelope; `data` is a JSON array of model names.
pub fn user_models_body(models: Vec<String>) -> Value {
    success_body(json!(models))
}

/// Go `common.H{"success": true, "message": "", "data": ...}`.
pub fn success_body(data: Value) -> Value {
    json!({
        "success": true,
        "message": "",
        "data": data,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn settings() -> GroupSettings {
        GroupSettings {
            group_ratio: BTreeMap::from([
                ("auto".to_owned(), 9.0),
                ("default".to_owned(), 1.0),
                ("free".to_owned(), 0.5),
                ("vip".to_owned(), 2.0),
            ]),
            user_usable_groups: BTreeMap::from([
                ("auto".to_owned(), "自动分组".to_owned()),
                ("default".to_owned(), "默认分组".to_owned()),
                ("vip".to_owned(), "vip分组".to_owned()),
            ]),
            group_group_ratio: BTreeMap::from([(
                "vip".to_owned(),
                BTreeMap::from([("default".to_owned(), 0.25)]),
            )]),
            group_special_usable_group: BTreeMap::new(),
            auto_groups: vec!["default".to_owned()],
        }
    }

    fn specials() -> BTreeMap<String, BTreeMap<String, String>> {
        BTreeMap::from([(
            "default".to_owned(),
            BTreeMap::from([
                ("+:vip".to_owned(), "VIP 分组".to_owned()),
                ("-:unavailable".to_owned(), String::new()),
            ]),
        )])
    }

    #[test]
    fn default_settings_produce_no_groups() {
        // Go's GroupRatio default is empty, so the default response has no
        // group entries even though UserUsableGroups has defaults.
        let body = success_body(user_groups_body(&GroupSettings::default(), ""));
        assert_eq!(body["success"], json!(true));
        assert_eq!(body["message"], json!(""));
        assert_eq!(body["data"], json!({}));
    }

    #[test]
    fn groups_keep_only_usable_ratio_keys_and_append_auto() {
        let body = success_body(user_groups_body(&settings(), ""));
        let data = body["data"].as_object().unwrap();
        assert_eq!(data.len(), 3);
        assert_eq!(data["default"]["ratio"].as_f64(), Some(1.0));
        assert_eq!(data["default"]["desc"], json!("默认分组"));
        assert_eq!(data["vip"]["ratio"].as_f64(), Some(2.0));
        assert_eq!(data["vip"]["desc"], json!("vip分组"));
        // `auto` is a string ratio, never a number.
        assert_eq!(data["auto"]["ratio"], json!("自动"));
        assert_eq!(data["auto"]["desc"], json!("自动分组"));
        assert!(!data.contains_key("free"));
    }

    #[test]
    fn user_specific_ratio_and_group_are_applied() {
        let body = success_body(user_groups_body(&settings(), "vip"));
        assert_eq!(body["data"]["default"]["ratio"].as_f64(), Some(0.25));

        // `custom` is in GroupRatio but not UserUsableGroups; Go adds the user
        // group itself with the literal description.
        let mut settings = settings();
        settings.group_ratio.insert("custom".to_owned(), 3.0);
        let body = success_body(user_groups_body(&settings, "custom"));
        assert_eq!(body["data"]["custom"]["ratio"].as_f64(), Some(3.0));
        assert_eq!(body["data"]["custom"]["desc"], json!("用户分组"));
    }

    #[test]
    fn groups_reflect_the_special_usable_group_overlay() {
        let mut settings = settings();
        settings
            .user_usable_groups
            .insert("unavailable".to_owned(), "不可用分组".to_owned());
        settings.group_ratio.insert("unavailable".to_owned(), 1.0);
        settings.group_special_usable_group = specials();
        let body = success_body(user_groups_body(&settings, "default"));
        let data = body["data"].as_object().unwrap();
        assert_eq!(data["vip"]["desc"], json!("VIP 分组"));
        assert!(!data.contains_key("unavailable"));
    }

    #[test]
    fn models_envelope_is_a_json_array() {
        assert_eq!(
            user_models_body(vec!["a".to_owned()]),
            json!({"success": true, "message": "", "data": ["a"]})
        );
    }

    #[test]
    fn models_select_all_usable_groups_without_a_query() {
        let settings = settings();
        let groups = user_models_groups(&settings, "default", None);
        assert_eq!(
            groups,
            vec!["auto".to_owned(), "default".to_owned(), "vip".to_owned()]
        );
        // `group=` is Go's empty query: same as absent.
        assert_eq!(user_models_groups(&settings, "default", Some("")), groups);
    }

    #[test]
    fn models_select_one_group_when_usable() {
        let settings = settings();
        assert_eq!(
            user_models_groups(&settings, "default", Some("vip")),
            vec!["vip".to_owned()]
        );
        // Not usable for this user: empty selection, matching Go's nil list.
        assert!(user_models_groups(&settings, "default", Some("free")).is_empty());
    }

    #[test]
    fn models_expand_auto_groups_in_configured_order() {
        // Go `TestGetUserModelsExpandsAutoGroupsInConfiguredOrder`:
        // AutoGroups [vip, default, unavailable] filtered by usability and
        // GroupRatio keeps [vip, default] in order; `unavailable` is removed
        // by the special overlay.
        let mut settings = settings();
        settings
            .user_usable_groups
            .insert("unavailable".to_owned(), "不可用分组".to_owned());
        settings.group_ratio.insert("unavailable".to_owned(), 1.0);
        settings.group_special_usable_group = specials();
        settings.auto_groups = vec![
            "vip".to_owned(),
            "default".to_owned(),
            "unavailable".to_owned(),
        ];
        assert_eq!(
            user_models_groups(&settings, "default", Some("auto")),
            vec!["vip".to_owned(), "default".to_owned()]
        );
    }

    #[test]
    fn models_auto_is_empty_when_auto_not_usable() {
        let mut settings = settings();
        settings.user_usable_groups.remove("auto");
        assert!(user_models_groups(&settings, "default", Some("auto")).is_empty());
    }

    #[test]
    fn requested_group_percent_decodes() {
        // Group names may need escaping; Go `c.Query` URL-decodes the value.
        let uri: Uri = "/api/user/models?group=vip%20pro".parse().unwrap();
        assert_eq!(requested_group(&uri).as_deref(), Some("vip pro"));
        let uri: Uri = "/api/user/models?group=a+b&group=vip".parse().unwrap();
        // The first matching pair wins, mirroring Go's single-value Query.
        assert_eq!(requested_group(&uri).as_deref(), Some("a b"));
        let uri: Uri = "/api/user/models".parse().unwrap();
        assert!(requested_group(&uri).is_none());
        let uri: Uri = "/api/user/models?other=1".parse().unwrap();
        assert!(requested_group(&uri).is_none());
    }
}
