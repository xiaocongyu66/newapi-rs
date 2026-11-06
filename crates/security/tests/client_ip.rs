//! trusted client IP 解析的契约测试，逐条对齐 Go 端
//! `ConfigureTrustedProxies` 与 `resolveTrustedClientIP`/`walkForwardedChain`。

use newapi_security::client_ip::{ProxyConfigError, ProxyPolicy, resolve_client_ip};
use std::net::IpAddr;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("测试用地址必须合法")
}

fn default_policy() -> ProxyPolicy {
    ProxyPolicy::parse_trusted_proxies(None).expect("默认策略必须合法")
}

fn parse(raw: Option<&str>) -> Result<ProxyPolicy, ProxyConfigError> {
    ProxyPolicy::parse_trusted_proxies(raw)
}

#[test]
fn unset_or_blank_falls_back_to_default_cidrs() {
    for raw in [None, Some(""), Some("   "), Some("\t ")] {
        let policy = parse(raw).expect("空白输入取默认列表");
        for trusted in [
            "127.0.0.1",
            "127.9.9.9",
            "10.1.2.3",
            "172.16.9.9",
            "172.31.255.255",
            "192.168.5.6",
            "::1",
            "fc00::abcd",
            "fd12:3456::1",
        ] {
            assert!(policy.trusts(ip(trusted)), "{trusted} 应在默认列表内");
        }
        for untrusted in [
            "8.8.8.8",
            "172.32.0.1",
            "169.254.1.1",
            "2001:db8::1",
            "fe80::1",
        ] {
            assert!(
                !policy.trusts(ip(untrusted)),
                "{untrusted} 不应被默认列表信任"
            );
        }
    }
}

#[test]
fn none_trusts_nothing_case_insensitively() {
    for raw in [Some("none"), Some("NONE"), Some("None"), Some("  none  ")] {
        let policy = parse(raw).expect("none 必须被接受");
        for candidate in ["127.0.0.1", "::1", "10.0.0.1", "192.168.0.1"] {
            assert!(!policy.trusts(ip(candidate)), "none 策略不应信任任何地址");
        }
    }
}

#[test]
fn none_mixed_into_list_is_rejected() {
    for raw in [
        Some("10.0.0.0/8, none"),
        Some("NONE,1.2.3.4"),
        Some("::1, None , 1.2.3.4"),
    ] {
        assert_eq!(
            parse(raw),
            Err(ProxyConfigError::NoneMustBeAlone),
            "混入的 none 必须报错"
        );
    }
}

#[test]
fn all_empty_entries_is_rejected() {
    for raw in [Some(","), Some(",,,"), Some(" , , ")] {
        assert_eq!(
            parse(raw),
            Err(ProxyConfigError::Empty),
            "仅逗号的列表必须报错"
        );
    }
}

#[test]
fn invalid_entries_are_rejected() {
    for raw in [
        Some("abc"),
        Some("10.0.0.256"),
        Some("010.0.0.1"),
        Some("10.0.0.0/33"),
        Some("10.0.0.0/"),
        Some("/8"),
        Some("2001:db8::/129"),
        Some("2001:db8::%eth0"),
        Some("2001:db8::/64/8"),
        Some("10.0.0.0/08x"),
        Some("1.2.3.4, garbage"),
    ] {
        assert_eq!(
            parse(raw),
            Err(ProxyConfigError::InvalidAddress),
            "非法地址或网段必须报错"
        );
    }
}

#[test]
fn explicit_list_with_blank_segments_parses() {
    let policy = parse(Some(" 10.0.0.0/8 , 1.2.3.4 , , ::1 "))
        .expect("trim 后空段应跳过，合法条目照常编译");
    assert!(policy.trusts(ip("10.9.9.9")));
    assert!(policy.trusts(ip("1.2.3.4")));
    // Go 将裸地址当作 /128 网段，非规范写法同样命中。
    assert!(policy.trusts(ip("0:0:0:0:0:0:0:1")));
    assert!(!policy.trusts(ip("1.2.3.5")));
    assert!(!policy.trusts(ip("11.0.0.1")));
    // 非规范网段被掩码归一：入口地址写作主机位同样匹配整段。
    let policy = parse(Some("10.0.5.7/24")).expect("Go 语义允许非规范网段");
    assert!(policy.trusts(ip("10.0.5.200")));
    assert!(!policy.trusts(ip("10.0.6.1")));
}

#[test]
fn error_display_never_leaks_input_values() {
    let error = parse(Some("1.2.3.4/999")).expect_err("必须失败");
    let text = error.to_string();
    assert!(!text.contains("1.2.3.4"));
    assert!(!text.contains("999"));
    assert_eq!(
        parse(Some("1.2.3.4, none")).expect_err("必须失败").to_string(),
        "TRUSTED_PROXIES=none must be used alone"
    );
    assert_eq!(
        parse(Some(",,")).expect_err("必须失败").to_string(),
        "TRUSTED_PROXIES does not contain an IP address or CIDR"
    );
}

#[test]
fn untrusted_peer_ignores_forged_headers() {
    let policy = default_policy();
    // 公网 peer 伪造 X-Forwarded-For 与 X-Real-IP，一律不采信。
    assert_eq!(
        resolve_client_ip(
            Some(ip("203.0.113.9")),
            Some("8.8.8.8, 1.1.1.1"),
            Some("9.9.9.9"),
            &policy
        ),
        "203.0.113.9"
    );
    // none 策略下即使 peer 是回环也不看头。
    let none = parse(Some("none")).expect("none 合法");
    assert_eq!(
        resolve_client_ip(Some(ip("127.0.0.1")), Some("8.8.8.8"), None, &none),
        "127.0.0.1"
    );
}

#[test]
fn missing_peer_resolves_to_empty() {
    assert_eq!(
        resolve_client_ip(None, Some("8.8.8.8"), Some("9.9.9.9"), &default_policy()),
        ""
    );
}

#[test]
fn trusted_peer_walks_chain_right_to_left() {
    let policy = default_policy();
    // 右起第一个不可信项胜出，左侧可伪造条目被跳过。
    assert_eq!(
        resolve_client_ip(
            Some(ip("127.0.0.1")),
            Some("1.1.1.1, 203.0.113.7, 10.0.0.1"),
            None,
            &policy
        ),
        "203.0.113.7"
    );
    // 全可信链由最左项胜出（i == 0 直接返回）。
    assert_eq!(
        resolve_client_ip(
            Some(ip("127.0.0.1")),
            Some("10.0.0.1, 192.168.0.2"),
            None,
            &policy
        ),
        "10.0.0.1"
    );
    // 单项头即最左项，trim 后原文返回。
    assert_eq!(
        resolve_client_ip(
            Some(ip("127.0.0.1")),
            Some(" 203.0.113.5 "),
            None,
            &policy
        ),
        "203.0.113.5"
    );
}

#[test]
fn malformed_entry_abandons_header_for_next_header() {
    let policy = default_policy();
    // XFF 最右项非法 → 整个 XFF 放弃，落到 X-Real-IP。
    assert_eq!(
        resolve_client_ip(
            Some(ip("127.0.0.1")),
            Some("1.1.1.1, evil"),
            Some("198.51.100.9"),
            &policy
        ),
        "198.51.100.9"
    );
    // 尾部空项同样按解析失败处理（Go 的 Split 会保留空串）。
    assert_eq!(
        resolve_client_ip(
            Some(ip("127.0.0.1")),
            Some("1.1.1.1,"),
            Some("198.51.100.9"),
            &policy
        ),
        "198.51.100.9"
    );
    // 两个头都不可用 → 回落 peer。
    assert_eq!(
        resolve_client_ip(Some(ip("127.0.0.1")), Some("evil"), Some("also evil"), &policy),
        "127.0.0.1"
    );
}

#[test]
fn empty_headers_are_skipped() {
    let policy = default_policy();
    // 空串头与缺失头等价（Go 的 c.Get 对缺失头返回空串）。
    assert_eq!(
        resolve_client_ip(Some(ip("127.0.0.1")), Some(""), Some("198.51.100.9"), &policy),
        "198.51.100.9"
    );
    // 头全缺失 → 回落 peer。
    assert_eq!(
        resolve_client_ip(Some(ip("127.0.0.1")), None, None, &policy),
        "127.0.0.1"
    );
}

#[test]
fn forwarded_for_takes_priority_over_real_ip() {
    let policy = default_policy();
    assert_eq!(
        resolve_client_ip(
            Some(ip("127.0.0.1")),
            Some("203.0.113.7"),
            Some("198.51.100.9"),
            &policy
        ),
        "203.0.113.7"
    );
}

#[test]
fn ipv4_mapped_addresses_demap_like_go() {
    let policy = default_policy();
    // Go 的 To4 使 ::ffff:127.0.0.1 命中 127.0.0.0/8。
    assert!(policy.trusts(ip("::ffff:127.0.0.1")));
    assert!(policy.trusts(ip("::ffff:10.1.2.3")));
    assert!(!policy.trusts(ip("::ffff:8.8.8.8")));
    // 非 ::ffff: 前缀不降级，回环的 v4 兼容写法不映射为 v4。
    assert!(!policy.trusts(ip("64:ff9b::7f00:1")));

    // 映射形态的 peer 按降级后的身份判定，回落输出点分形式（Go IP.String 语义）。
    assert_eq!(
        resolve_client_ip(Some(ip("::ffff:127.0.0.1")), None, None, &policy),
        "127.0.0.1"
    );
    assert_eq!(
        resolve_client_ip(Some(ip("::ffff:8.8.8.8")), Some("1.1.1.1"), None, &policy),
        "8.8.8.8"
    );

    // 映射形态书写的网段：/104 等价于 v4 的 /8。
    let policy = parse(Some("::ffff:10.0.0.0/104")).expect("Is4In6 网段前缀上限为 128");
    assert!(policy.trusts(ip("10.5.0.1")));
    assert!(policy.trusts(ip("::ffff:10.5.0.1")));
    assert!(!policy.trusts(ip("11.0.0.1")));
    // 纯 v6 网段不匹配 v4 地址，反之亦然。
    let policy = parse(Some("2001:db8::/32")).expect("v6 网段合法");
    assert!(policy.trusts(ip("2001:db8::1")));
    assert!(!policy.trusts(ip("10.0.0.1")));
}

#[test]
fn bare_mapped_address_matches_v4_entry() {
    // 裸地址条目同样吃 To4 降级：1.2.3.4 条目命中 ::ffff:1.2.3.4。
    let policy = parse(Some("1.2.3.4")).expect("裸地址合法");
    assert!(policy.trusts(ip("::ffff:1.2.3.4")));
    assert!(policy.trusts(ip("1.2.3.4")));
    assert!(!policy.trusts(ip("::1.2.3.4")));
}
