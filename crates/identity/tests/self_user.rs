use std::collections::BTreeMap;

use newapi_identity::self_user::{Permissions, SelfUserInput, SidebarModulePermission, assemble};
use newapi_identity::users::UserProfile;
use serde_json::json;

fn profile(setting: &str) -> UserProfile {
    UserProfile {
        id: 17,
        username: " 用户' OR 1=1 -- ".into(),
        display_name: " 原样名称 ".into(),
        role: 100,
        status: 2,
        email: "fixture@example.invalid".into(),
        github_id: "github-fixture".into(),
        discord_id: "discord-fixture".into(),
        oidc_id: "oidc-fixture".into(),
        wechat_id: "wechat-fixture".into(),
        telegram_id: "telegram-fixture".into(),
        group: " 非默认组 ".into(),
        quota: i64::MAX,
        used_quota: 2_147_483_648,
        request_count: 456,
        aff_code: "aff-fixture".into(),
        aff_count: 7,
        aff_quota: -91,
        aff_history_quota: 123_456_789,
        inviter_id: 9,
        linux_do_id: "linux-do-fixture".into(),
        setting: setting.into(),
        stripe_customer: "stripe-fixture".into(),
    }
}

fn permissions(sidebar_settings: bool, allowed: bool) -> Permissions {
    Permissions {
        sidebar_settings,
        sidebar_modules: BTreeMap::from([
            ("personal".into(), SidebarModulePermission::Enabled(true)),
            (
                "admin".into(),
                SidebarModulePermission::Actions(BTreeMap::from([("setting".into(), allowed)])),
            ),
        ]),
        admin_permissions: BTreeMap::from([(
            "fixture_resource".into(),
            BTreeMap::from([("read".into(), allowed), ("write".into(), false)]),
        )]),
    }
}

#[test]
fn all_profile_fields_and_permissions_are_preserved() {
    let setting = " {\"sidebar_modules\":\"fixture\",\"unknown\":true} \n";
    let supplied_permissions = permissions(false, false);
    let expected_permissions = supplied_permissions.clone();
    let user = assemble(SelfUserInput {
        profile: profile(setting),
        permissions: supplied_permissions,
    });
    assert_eq!(user.permissions, expected_permissions);
    let serialized_profile = serde_json::to_value(&user.profile).expect("serialize profile");
    let expected_profile = json!({
        "id": 17,
        "username": " 用户' OR 1=1 -- ",
        "display_name": " 原样名称 ",
        "role": 100,
        "status": 2,
        "email": "fixture@example.invalid",
        "github_id": "github-fixture",
        "discord_id": "discord-fixture",
        "oidc_id": "oidc-fixture",
        "wechat_id": "wechat-fixture",
        "telegram_id": "telegram-fixture",
        "group": " 非默认组 ",
        "quota": i64::MAX,
        "used_quota": 2_147_483_648_i64,
        "request_count": 456,
        "aff_code": "aff-fixture",
        "aff_count": 7,
        "aff_quota": -91,
        "aff_history_quota": 123_456_789,
        "inviter_id": 9,
        "linux_do_id": "linux-do-fixture",
        "setting": setting,
        "stripe_customer": "stripe-fixture",
    });
    assert_eq!(serialized_profile, expected_profile);

    let serialized = serde_json::to_value(&user).expect("serialize self user");
    let mut expected = expected_profile;
    expected["permissions"] = json!({
        "sidebar_settings": false,
        "sidebar_modules": {"personal": true, "admin": {"setting": false}},
        "admin_permissions": {"fixture_resource": {"read": false, "write": false}},
    });
    // 完整白名单比较也排除派生额度、侧栏、管理员备注与嵌套 profile。
    assert_eq!(serialized, expected);
    let object = serialized.as_object().expect("self user object");
    for forbidden in ["password", "token", "access_token", "auth_version", "remark"] {
        assert!(!object.contains_key(forbidden));
    }
}

#[test]
fn setting_is_never_parsed_or_normalized() {
    for setting in ["not-json", "", " null ", " {\"sidebar_modules\":false} \n"] {
        let user = assemble(SelfUserInput {
            profile: profile(setting),
            permissions: permissions(false, false),
        });
        assert_eq!(user.profile.setting, setting);
        let serialized = serde_json::to_value(user).expect("serialize raw setting");
        assert_eq!(serialized["setting"], json!(setting));
        assert!(serialized.get("sidebar_modules").is_none());
    }
}

#[test]
fn construction_requires_explicit_permissions_and_preserves_them() {
    // 输入没有 Default 或省略权限的构造路径；构造表达式必须给出权限字段。
    // 即使 role=100，组装层也不覆盖显式拒绝或推导授权。
    for (sidebar_settings, allowed) in [(false, false), (true, true), (true, false)] {
        let supplied = permissions(sidebar_settings, allowed);
        let expected = supplied.clone();
        let input = SelfUserInput {
            profile: profile("raw"),
            permissions: supplied,
        };
        assert_eq!(input.permissions, expected);
        let user = assemble(input);
        assert_eq!(user.permissions, expected);
        assert_eq!(user.profile.group, " 非默认组 ");
    }
}
