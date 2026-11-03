use std::collections::BTreeMap;

use newapi_identity::self_user::{
    Permissions, QuotaDisplayKind, QuotaDisplaySettings, SelfUserInput, SidebarModulePermission,
    assemble,
};

fn usd() -> QuotaDisplaySettings {
    QuotaDisplaySettings {
        quota_per_unit: 500_000.0,
        kind: QuotaDisplayKind::Usd,
    }
}
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
        display: usd(),
        sidebar_modules: "{\"personal\":true}".into(),
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
        "quota_display": 9_223_372_036_854_775_808.0_f64 / 500_000.0,
        "used_quota": 2_147_483_648_i64,
        "used_quota_display": 2_147_483_648.0_f64 / 500_000.0,
        "request_count": 456,
        "aff_code": "aff-fixture",
        "aff_count": 7,
        "aff_quota": -91,
        "aff_quota_display": -91.0_f64 / 500_000.0,
        "aff_history_quota": 123_456_789,
        "aff_history_quota_display": 123_456_789.0_f64 / 500_000.0,
        "inviter_id": 9,
        "linux_do_id": "linux-do-fixture",
        "setting": setting,
        "stripe_customer": "stripe-fixture",
        "sidebar_modules": "{\"personal\":true}",
    });
    assert_eq!(serialized_profile, expected_profile);

    let serialized = serde_json::to_value(&user).expect("serialize self user");
    let mut expected = expected_profile;
    expected["permissions"] = json!({
        "sidebar_settings": false,
        "sidebar_modules": {"personal": true, "admin": {"setting": false}},
        "admin_permissions": {"fixture_resource": {"read": false, "write": false}},
    });
    // 完整白名单比较也排除密码、令牌、内部版本与管理员备注。
    assert_eq!(serialized, expected);
    let object = serialized.as_object().expect("self user object");
    for forbidden in [
        "password",
        "token",
        "access_token",
        "auth_version",
        "remark",
    ] {
        assert!(!object.contains_key(forbidden));
    }
}

#[test]
fn setting_is_never_parsed_or_normalized() {
    for setting in ["not-json", "", " null ", " {\"sidebar_modules\":false} \n"] {
        let user = assemble(SelfUserInput {
            profile: profile(setting),
            permissions: permissions(false, false),
            display: usd(),
            sidebar_modules: setting.into(),
        });
        assert_eq!(user.profile.setting, setting);
        let serialized = serde_json::to_value(user).expect("serialize raw setting");
        assert_eq!(serialized["setting"], json!(setting));
        // 侧栏数据由调用方提供，组装层不解析 setting。
        assert_eq!(serialized["sidebar_modules"], json!(setting));
    }
}

#[test]
fn quota_display_follows_go_billing_branches() {
    let quota = 1_000_000_i64;
    let cases = [
        (QuotaDisplayKind::Usd, 2.0),
        (
            QuotaDisplayKind::Cny {
                usd_exchange_rate: 7.3,
            },
            14.6,
        ),
        (QuotaDisplayKind::Custom { rate: 2.5 }, 5.0),
        (QuotaDisplayKind::Custom { rate: 0.0 }, 2.0),
        (QuotaDisplayKind::Custom { rate: -1.0 }, 2.0),
        (QuotaDisplayKind::Tokens, 1_000_000.0),
    ];
    for (kind, expected) in cases {
        let settings = QuotaDisplaySettings {
            quota_per_unit: 500_000.0,
            kind,
        };
        assert!((settings.to_display(quota) - expected).abs() < 1e-9);
    }
}

#[test]
fn non_finite_quota_displays_fail_serialization_instead_of_becoming_null() {
    let cases = [
        QuotaDisplaySettings {
            quota_per_unit: 0.0,
            kind: QuotaDisplayKind::Usd,
        },
        QuotaDisplaySettings {
            quota_per_unit: f64::NAN,
            kind: QuotaDisplayKind::Usd,
        },
        QuotaDisplaySettings {
            quota_per_unit: 500_000.0,
            kind: QuotaDisplayKind::Cny {
                usd_exchange_rate: f64::INFINITY,
            },
        },
        QuotaDisplaySettings {
            quota_per_unit: 500_000.0,
            kind: QuotaDisplayKind::Custom { rate: f64::NAN },
        },
        QuotaDisplaySettings {
            quota_per_unit: 1.0,
            kind: QuotaDisplayKind::Custom { rate: f64::MAX },
        },
    ];
    for display in cases {
        let user = assemble(SelfUserInput {
            profile: profile("raw"),
            permissions: permissions(false, false),
            display,
            sidebar_modules: String::new(),
        });
        assert!(serde_json::to_value(&user).is_err());
        assert!(serde_json::to_string(&user).is_err());
    }

    for field in 0..4 {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let mut user = assemble(SelfUserInput {
                profile: profile("raw"),
                permissions: permissions(false, false),
                display: usd(),
                sidebar_modules: String::new(),
            });
            match field {
                0 => user.profile.quota_display = value,
                1 => user.profile.used_quota_display = value,
                2 => user.profile.aff_quota_display = value,
                _ => user.profile.aff_history_quota_display = value,
            }
            assert!(serde_json::to_value(&user).is_err());
            assert!(serde_json::to_string(&user).is_err());
            let error = serde_json::to_value(&user.profile)
                .expect_err("非有限展示字段不能被单独序列化为 null");
            assert!(error.to_string().contains("non-finite quota display"));
        }
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
            display: usd(),
            sidebar_modules: String::new(),
        };
        assert_eq!(input.permissions, expected);
        let user = assemble(input);
        assert_eq!(user.permissions, expected);
        assert_eq!(user.profile.group, " 非默认组 ");
    }
}
