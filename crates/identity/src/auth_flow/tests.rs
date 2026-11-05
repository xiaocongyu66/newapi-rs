use super::AuthFlowError;
use super::token::{
    PURPOSE_TWO_FA_LOGIN, Purpose, TOKEN_BYTES, auth_flow_key, generate_token, token_hash,
};

#[test]
fn purpose_matches_go_constant() {
    assert_eq!(Purpose::TwoFALogin, "2fa_login");
    assert_eq!(PURPOSE_TWO_FA_LOGIN, "2fa_login");
}

#[test]
fn key_matches_go_byte_format() {
    assert_eq!(
        auth_flow_key("test-secret"),
        b"auth-flow-v1:test-secret".to_vec()
    );
}

#[test]
fn token_hash_is_lower_hex_hmac_sha256() {
    let key = auth_flow_key("test-secret");
    // Python: hmac.new(b"auth-flow-v1:test-secret", b"abc", sha256).hexdigest()
    assert_eq!(
        token_hash(&key, "abc"),
        "cfcaec2ba16faeefa20033b85bb8f995c54dc9836139dd9b8e8547552d139c21"
    );
    let first = token_hash(&key, "abc");
    assert_eq!(first, token_hash(&key, "abc"), "HMAC must be deterministic");
    assert_ne!(token_hash(&key, "abc"), token_hash(&key, "abd"));
    assert_ne!(
        token_hash(&key, "abc"),
        token_hash(&auth_flow_key("other"), "abc")
    );
    let hash = token_hash(&key, "abc");
    assert_eq!(hash.len(), 64);
    assert!(
        hash.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
}

#[test]
fn generated_token_is_32_random_bytes_raw_url() {
    let first = generate_token().expect("generate token");
    let second = generate_token().expect("generate token");
    for token in [&first, &second] {
        let raw = token.expose_secret();
        // 32 bytes => 43 RawURL characters and no padding.
        assert_eq!(raw.len(), 43);
        assert!(!raw.contains('='));
        assert!(
            raw.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }
    assert_ne!(first.expose_secret(), second.expose_secret());
    assert_eq!(TOKEN_BYTES, 32);
}

#[test]
fn errors_do_not_expose_token_or_sql() {
    for error in [
        AuthFlowError::Invalid,
        AuthFlowError::Expired,
        AuthFlowError::Consumed,
        AuthFlowError::Storage,
    ] {
        let text = error.to_string();
        assert!(!text.contains("token="));
        assert!(!text.contains("SELECT"));
        assert!(!text.contains("INSERT"));
    }
}
