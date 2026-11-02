use newapi_security::{
    ApiKeyGrant, ApiKeyMode, ApiKeyStatus, AuthContext, CredentialKind, Denial, OriginRequest, Role,
    authorize_role, check_api_key, check_ip_allowlist, check_session_origin, require_browser_session,
};

fn auth(kind: CredentialKind) -> AuthContext<'static> {
    AuthContext {
        user_id: 7,
        username: "测试用户",
        role: Role::User,
        user_enabled: true,
        credential: kind,
        session_id: Some("测试会话"),
    }
}

#[test]
fn role_values_and_thresholds_are_exact() {
    for invalid in [-1, 0, 2, 9, 11, 99, 101] {
        assert_eq!(Role::try_from(invalid), Err(Denial::InvalidUser));
    }
    for (value, role) in [(1, Role::User), (10, Role::Admin), (100, Role::Root)] {
        assert_eq!(Role::try_from(value), Ok(role));
        let mut context = auth(CredentialKind::DashboardSession);
        context.role = role;
        for minimum in [Role::User, Role::Admin, Role::Root] {
            assert_eq!(authorize_role(&context, minimum).is_ok(), role >= minimum);
        }
    }
}

#[test]
fn credentials_are_not_interchangeable() {
    for kind in [
        CredentialKind::DashboardSession,
        CredentialKind::PersonalAccessToken,
        CredentialKind::RelayApiKey,
        CredentialKind::RefreshToken,
        CredentialKind::SecurityProof,
        CredentialKind::LoginFlow,
    ] {
        let context = auth(kind);
        assert_eq!(
            authorize_role(&context, Role::User).is_ok(),
            matches!(
                kind,
                CredentialKind::DashboardSession | CredentialKind::PersonalAccessToken
            )
        );
        assert_eq!(
            require_browser_session(&context).is_ok(),
            kind == CredentialKind::DashboardSession
        );
        assert_eq!(
            check_api_key(
                &context,
                &grant(),
                ApiKeyMode::Full,
                100,
                "127.0.0.1".parse().unwrap()
            )
            .is_ok(),
            kind == CredentialKind::RelayApiKey
        );
    }
    let mut context = auth(CredentialKind::DashboardSession);
    context.session_id = None;
    assert_eq!(
        require_browser_session(&context),
        Err(Denial::BrowserSessionRequired)
    );
    context.user_enabled = false;
    assert_eq!(
        authorize_role(&context, Role::User),
        Err(Denial::UserDisabled)
    );
    context.user_enabled = true;
    context.username = "  ";
    assert_eq!(
        authorize_role(&context, Role::User),
        Err(Denial::InvalidUser)
    );
}

fn grant() -> ApiKeyGrant<'static> {
    ApiKeyGrant {
        owner_id: 7,
        deleted: false,
        status: ApiKeyStatus::Enabled,
        expires_at: 100,
        unlimited_quota: false,
        remaining_quota: 1,
        allowed_ips: &[],
    }
}

#[test]
fn api_key_readonly_and_full_boundaries() {
    let context = auth(CredentialKind::RelayApiKey);
    let ip = "127.0.0.1".parse().unwrap();
    let mut key = grant();
    assert_eq!(check_api_key(&context, &key, ApiKeyMode::Full, 100, ip), Ok(()));
    assert_eq!(
        check_api_key(&context, &key, ApiKeyMode::Full, 101, ip),
        Err(Denial::ApiKeyExpired)
    );
    key.expires_at = -1;
    key.remaining_quota = 0;
    assert_eq!(
        check_api_key(&context, &key, ApiKeyMode::Full, 101, ip),
        Err(Denial::ApiKeyExhausted)
    );
    key.unlimited_quota = true;
    assert_eq!(check_api_key(&context, &key, ApiKeyMode::Full, 101, ip), Ok(()));
    key.allowed_ips = &["192.0.2.0/24"];
    assert_eq!(
        check_api_key(&context, &key, ApiKeyMode::Full, 101, ip),
        Err(Denial::IpForbidden)
    );
    for status in [
        ApiKeyStatus::Enabled,
        ApiKeyStatus::Expired,
        ApiKeyStatus::Exhausted,
    ] {
        key.status = status;
        assert_eq!(
            check_api_key(&context, &key, ApiKeyMode::ReadOnly, 101, ip),
            Ok(())
        );
    }
    key.status = ApiKeyStatus::Disabled;
    for mode in [ApiKeyMode::ReadOnly, ApiKeyMode::Full] {
        assert_eq!(
            check_api_key(&context, &key, mode, 101, ip),
            Err(Denial::ApiKeyDisabled)
        );
    }
    key.status = ApiKeyStatus::Enabled;
    key.owner_id = 8;
    assert_eq!(
        check_api_key(&context, &key, ApiKeyMode::ReadOnly, 101, ip),
        Err(Denial::InvalidApiKey)
    );
    key.owner_id = 7;
    key.deleted = true;
    assert_eq!(
        check_api_key(&context, &key, ApiKeyMode::ReadOnly, 101, ip),
        Err(Denial::InvalidApiKey)
    );
}

#[test]
fn ipv4_ipv6_and_malformed_networks() {
    for (entries, ip, expected) in [
        (vec!["192.0.2.0/24"], "192.0.2.9", Ok(())),
        (vec!["2001:db8::/32"], "2001:db8::1", Ok(())),
        (vec!["::1"], "::1", Ok(())),
        (vec!["::1"], "127.0.0.1", Err(Denial::IpForbidden)),
        (vec!["127.0.0.1", "坏配置"], "127.0.0.1", Err(Denial::InvalidIpPolicy)),
        (vec!["192.0.2.0/33"], "192.0.2.1", Err(Denial::InvalidIpPolicy)),
    ] {
        assert_eq!(check_ip_allowlist(&entries, ip.parse().unwrap()), expected);
    }
}

fn origin_request<'a>(origins: &'a [&'a str]) -> OriginRequest<'a> {
    OriginRequest {
        secure_cookie: true,
        transport_tls: true,
        host_headers: &["example.test"],
        origin_headers: origins,
        referer_headers: &[],
        trusted_urls: &[],
    }
}

#[test]
fn origin_normalization_and_hostile_inputs() {
    for origin in [
        "https://example.test",
        "https://EXAMPLE.test:443",
        " https://example.test/ ",
        "https://example.test?",
        "https://example.test#",
        "https://example.test:",
    ] {
        assert_eq!(check_session_origin(&origin_request(&[origin])), Ok(()));
    }
    for origin in [
        "null",
        "",
        "https://example.test:444",
        "http://example.test",
        "https://example.test.evil.test",
        "https://example.test@evil.test",
        "https://evil.test@example.test",
        "https://@example.test",
        "https://example.test,https://example.test",
        "https://example.test https://evil.test",
        "https://example.test/path",
        // 原始路径已有斜线，转义斜线解码后为双斜线，不是根路径。
        "https://example.test/%2f",
        "https://example.test/a/..",
        "https://example.test/%2e",
        "https://example.test/%2E%2e/",
        "https://example.test/./",
        "https://example.test/%",
        "https://example.test:0443",
        "https://example.test?query=1",
        "https://example.test#fragment",
        "https:///example.test",
        "https://example.test\\@evil.test",
        "https://example.\ntest",
    ] {
        assert_eq!(
            check_session_origin(&origin_request(&[origin])),
            Err(Denial::OriginForbidden)
        );
    }
}

#[test]
fn origin_duplicates_fallback_and_insecure_compatibility() {
    let mut request = origin_request(&[]);
    assert_eq!(check_session_origin(&request), Err(Denial::OriginForbidden));
    for referer in [
        "https://example.test/page?email=a@b.test",
        "https://example.test/a@b,c?values=1,2",
        "https://example.test/a/..",
    ] {
        let referers = [referer];
        let mut fallback = origin_request(&[]);
        fallback.referer_headers = &referers;
        assert_eq!(check_session_origin(&fallback), Ok(()));
    }
    request.referer_headers = &["https://evil.test@example.test/page"];
    assert_eq!(check_session_origin(&request), Err(Denial::OriginForbidden));
    request.origin_headers = &["https://example.test"];
    request.referer_headers = &["not a URL", "https://evil.test/page"];
    assert_eq!(check_session_origin(&request), Ok(()));
    request.origin_headers = &["null"];
    assert_eq!(check_session_origin(&request), Err(Denial::OriginForbidden));
    request.origin_headers = &["https://example.test", "https://example.test"];
    assert_eq!(check_session_origin(&request), Err(Denial::OriginForbidden));
    request.origin_headers = &[];
    request.referer_headers = &["https://example.test/a", "https://example.test/b"];
    assert_eq!(check_session_origin(&request), Err(Denial::OriginForbidden));
    request.secure_cookie = false;
    assert_eq!(check_session_origin(&request), Ok(()));
}

#[test]
fn raw_host_and_port_equivalence_matches_go() {
    for (host, origin, allowed) in [
        ("127.0.0.1", "https://127.1", false),
        ("127.0.0.1", "https://2130706433", false),
        ("127.0.0.1", "https://0x7f000001", false),
        ("xn--bcher-kva.test", "https://bücher.test", false),
        ("bücher.test", "https://BÜCHER.test", true),
        ("example.test", "https://example.test:0443", false),
        ("example.test:0443", "https://example.test:0443", true),
        ("example.test:70000", "https://example.test:70000", true),
        ("127.1", "https://127.1", true),
    ] {
        let hosts = [host];
        let origins = [origin];
        let mut request = origin_request(&origins);
        request.host_headers = &hosts;
        assert_eq!(check_session_origin(&request).is_ok(), allowed);
    }
}

#[test]
fn transport_scheme_ports_ipv6_and_trusted_urls() {
    let mut request = origin_request(&["https://example.test"]);
    // 即使请求声称经过安全代理，非加密连接也不自动成为安全来源。
    request.transport_tls = false;
    assert_eq!(check_session_origin(&request), Err(Denial::OriginForbidden));
    request.trusted_urls = &["https://example.test"];
    assert_eq!(check_session_origin(&request), Ok(()));
    request.trusted_urls = &[];
    request.transport_tls = true;
    request.host_headers = &["[2001:db8::1]:8443"];
    request.origin_headers = &["https://[2001:0db8::1]:8443"];
    assert_eq!(check_session_origin(&request), Err(Denial::OriginForbidden));
    request.origin_headers = &["https://[2001:DB8::1]:8443"];
    assert_eq!(check_session_origin(&request), Ok(()));
    request.origin_headers = &["https://[2001:db8::1]"];
    assert_eq!(check_session_origin(&request), Err(Denial::OriginForbidden));
    request.host_headers = &["example.test", "example.test"];
    assert_eq!(check_session_origin(&request), Err(Denial::OriginForbidden));
    request.host_headers = &["evil.test@example.test"];
    assert_eq!(check_session_origin(&request), Err(Denial::OriginForbidden));
}
