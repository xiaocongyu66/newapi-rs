//! `GET /api/user/groups`, `GET /api/user/self/groups`, and
//! `GET /api/user/models` HTTP adapters.
//!
//! Go references:
//! - `apps/api/internal/transport/handler/handle_group.go` (`GetUserGroups`)
//! - `apps/api/internal/identity/manage_users.go` (`GetUserModels`)
//! - `apps/api/internal/transport/compose/register_api.go` (route wiring)
//!
//! `GET /api/user/groups` is registered without `UserAuth` in Go, so
//! `c.GetInt("id")` is 0 and the user group is empty. `GET
//! /api/user/self/groups` runs behind `UserAuth` and therefore sees the
//! authenticated user's group. Both routes share [`user_groups`] here; the
//! optional extension is present only when the router applied
//! [`crate::auth::user_auth`], which reproduces the Go difference.
//!
//! Model resolution is not ported yet: the catalog crate has no `abilities` /
//! `channels` repository, so [`user_models`] returns the empty list Go returns
//! when its resolver hook is unregistered. The TODO below marks the seam; no
//! model data is fabricated.

use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
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
    let settings = match load_settings(&state).await {
        Ok(settings) => settings,
        Err(response) => return *response,
    };
    Json(success_body(user_groups_body(&settings, user_group))).into_response()
}

/// `GET /api/user/models`.
///
/// Go `identity.GetUserModels` reads the authenticated user, selects the groups
/// from the `group` query parameter (`auto` expands to the ordered auto-group
/// list), and resolves models from the `abilities` table. The selection rules
/// and the `abilities` lookup belong to a later slice; the response shape is
/// final and the data is the empty list.
pub async fn user_models(
    State(_state): State<AppState>,
    Extension(_authenticated): Extension<AuthenticatedUser>,
) -> Response {
    // TODO(groups-models): load `GroupSettings` here, port the
    // `userUsableGroups`/`userAutoGroup` selection, and run
    // `SELECT DISTINCT model FROM abilities WHERE "group" = ? AND enabled = ?`
    // once the catalog owns an abilities repository. Go returns an empty list
    // while its resolver hook is unregistered, which this matches.
    Json(success_body(user_models_body(Vec::new()))).into_response()
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

async fn load_settings(state: &AppState) -> Result<GroupSettings, Box<Response>> {
    let Some(db) = state.db() else {
        return Err(Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()));
    };
    match GroupSettings::load(&db, &GroupSettings::default()).await {
        Ok(settings) => Ok(settings),
        Err(error) => {
            tracing::warn!(
                event = "group_settings_load_failed",
                category = crate::database_error_class(&error),
                "group settings load failed"
            );
            Err(Box::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))
        }
    }
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
        }
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
    fn models_envelope_is_an_empty_array() {
        assert_eq!(
            user_models_body(Vec::new()),
            json!({"success": true, "message": "", "data": []})
        );
    }
}
