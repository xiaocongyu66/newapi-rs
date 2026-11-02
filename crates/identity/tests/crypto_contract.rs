use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use newapi_identity::crypto::{
    AuthKeys, RefreshCredential, hash_password_with_salt, verify_password,
};
use newapi_identity::tokens::{DashboardAccess, classify_dashboard};
use newapi_identity::{AuthError, AuthIdentity, CredentialKind};
use serde_json::{Value, json};
use sha2::Sha256;

const SECRET: &str = "test-session-secret-with-sufficient-entropy";
const NOW: i64 = 1_700_000_000;
const JTI: &str = "11111111-2222-4333-8444-555555555555";
const SID: &str = "123e4567-e89b-42d3-a456-426614174000";

fn identity() -> AuthIdentity {
    AuthIdentity {
        user_id: 42,
        sid: "session-1".to_owned(),
        user_auth_version: 3,
        session_version: 2,
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn lowerhex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn claims() -> Value {
    json!({
        "token_use":"access", "sid":"session-1", "uv":3, "sv":2,
        "iss":"new-api", "sub":"42", "aud":["new-api-dashboard"],
        "exp":NOW+900, "nbf":NOW-5, "iat":NOW, "jti":JTI,
    })
}

fn sign(value: &Value, purpose: &str, alg: &str) -> String {
    let key = hmac(
        SECRET.as_bytes(),
        format!("new-api/auth/{purpose}/v1").as_bytes(),
    );
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(json!({"alg":alg,"typ":"JWT"}).to_string()),
        URL_SAFE_NO_PAD.encode(value.to_string())
    );
    format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(hmac(&key, input.as_bytes()))
    )
}

#[test]
fn go_bcrypt_known_answer_and_legacy_versions() {
    // 金标准来源：golang.org/x/crypto v0.41.0 bcrypt_test.go 的公开合成向量。
    // 对应 TestBcryptingIsCorrect 和 TestUnpaddedBase64Encoding，非生产凭据。
    let expected = "$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga";
    let salt = [
        101, 201, 101, 75, 19, 227, 199, 20, 239, 236, 133, 32, 30, 109, 243, 30,
    ];
    let generated = hash_password_with_salt(b"allmine", salt).unwrap();
    assert!(generated.expose_secret() == expected);
    for version in ["2a", "2b", "2x", "2y", "2", "2z"] {
        let stored = format!("${version}$10${}", &expected[7..]);
        assert!(verify_password(b"allmine", &stored).unwrap());
        assert!(!verify_password(b" allmine", &stored).unwrap());
    }
    assert!(!verify_password(b"allmine", "").unwrap());
    assert!(!verify_password(b"allmine", "allmine").unwrap());
    assert!(!verify_password(b"allmine", &expected.replacen("$2", "$3", 1)).unwrap());
}

#[test]
fn password_byte_boundaries_nul_and_unicode() {
    let long = [b'x'; 73];
    assert!(matches!(
        hash_password_with_salt(&long, [0; 16]),
        Err(AuthError::PasswordTooLong)
    ));
    let stored = hash_password_with_salt(&long[..72], [0; 16]).unwrap();
    assert!(verify_password(&long, stored.expose_secret()).unwrap());
    assert!(verify_password(&long[..72], stored.expose_secret()).unwrap());
    assert!(!verify_password(&long[..71], stored.expose_secret()).unwrap());
    let stored = hash_password_with_salt("密码\0尾部 ".as_bytes(), [1; 16]).unwrap();
    assert!(verify_password("密码\0尾部 ".as_bytes(), stored.expose_secret()).unwrap());
    assert!(!verify_password("密码".as_bytes(), stored.expose_secret()).unwrap());
    assert!(!verify_password("密码\0尾部".as_bytes(), stored.expose_secret()).unwrap());
    assert!(hash_password_with_salt("密".repeat(24).as_bytes(), [2; 16]).is_ok());
    assert!(matches!(
        hash_password_with_salt("密".repeat(25).as_bytes(), [2; 16]),
        Err(AuthError::PasswordTooLong)
    ));
}

#[test]
fn access_claims_and_exact_go_serialization_order() {
    let keys = AuthKeys::new(SECRET);
    let issued = keys.issue_access_with_jti(&identity(), NOW, JTI).unwrap();
    assert_eq!(issued.expires_at, NOW + 900);
    let raw = issued.token.expose_secret();
    assert_eq!(keys.parse_access(raw, NOW).unwrap(), identity());
    let payload = raw.split('.').nth(1).unwrap();
    let decoded = URL_SAFE_NO_PAD.decode(payload).unwrap();
    let expected = format!(
        r#"{{"token_use":"access","sid":"session-1","uv":3,"sv":2,"iss":"new-api","sub":"42","aud":["new-api-dashboard"],"exp":1700000900,"nbf":1699999995,"iat":1700000000,"jti":"{JTI}"}}"#
    );
    assert!(decoded == expected.as_bytes());
    assert_eq!(classify_dashboard(raw), CredentialKind::InternalDashboard);
    assert!(keys.parse_access(raw, NOW + 904).is_ok());
    assert_eq!(keys.parse_access(raw, NOW + 905), Err(AuthError::Expired));
    assert!(keys.parse_access(raw, NOW - 5).is_ok());
    assert_eq!(keys.parse_access(raw, NOW - 6), Err(AuthError::Invalid));
}

#[test]
fn mandatory_claims_types_algorithms_and_time_edges() {
    let keys = AuthKeys::new(SECRET);
    for field in [
        "exp",
        "nbf",
        "iat",
        "jti",
        "iss",
        "sub",
        "aud",
        "sid",
        "uv",
        "sv",
        "token_use",
    ] {
        let mut value = claims();
        value.as_object_mut().unwrap().remove(field);
        assert!(
            keys.parse_access(&sign(&value, "access", "HS256"), NOW)
                .is_err()
        );
        value[field] = Value::Null;
        assert!(
            keys.parse_access(&sign(&value, "access", "HS256"), NOW)
                .is_err()
        );
    }
    for field in ["iat", "nbf"] {
        let mut value = claims();
        value[field] = json!(NOW + 5);
        assert!(
            keys.parse_access(&sign(&value, "access", "HS256"), NOW)
                .is_ok()
        );
        value[field] = json!(NOW + 6);
        assert!(
            keys.parse_access(&sign(&value, "access", "HS256"), NOW)
                .is_err()
        );
    }
    for alg in ["none", "HS384", "RS256"] {
        assert!(
            keys.parse_access(&sign(&claims(), "access", alg), NOW)
                .is_err()
        );
    }
    for (field, bad) in [
        ("uv", json!(0)),
        ("sv", json!(-1)),
        ("sid", json!("")),
        ("sub", json!("0")),
        ("jti", json!("")),
        ("iss", json!("other")),
        ("aud", json!(["other"])),
    ] {
        let mut value = claims();
        value[field] = bad;
        assert!(
            keys.parse_access(&sign(&value, "access", "HS256"), NOW)
                .is_err()
        );
    }
    let mut value = claims();
    value["aud"] = json!("new-api-dashboard");
    assert!(
        keys.parse_access(&sign(&value, "access", "HS256"), NOW)
            .is_ok()
    );
}

#[test]
fn proof_binding_scope_method_and_purpose_isolation() {
    let keys = AuthKeys::new(SECRET);
    let scopes = vec!["password:update".to_owned()];
    let proof = keys
        .issue_security_proof_with_jti(&identity(), " totp ", &scopes, NOW, JTI)
        .unwrap();
    let raw = proof.token.expose_secret();
    assert_eq!(proof.expires_at, NOW + 300);
    assert_eq!(
        keys.verify_security_proof(raw, &identity(), "password:update", &[], NOW)
            .unwrap(),
        "totp"
    );
    assert_eq!(
        keys.verify_security_proof(raw, &identity(), "password", &[], NOW),
        Err(AuthError::ProofScope)
    );
    assert_eq!(
        keys.verify_security_proof(raw, &identity(), "", &["passkey".to_owned()], NOW),
        Err(AuthError::ProofMethod)
    );
    assert!(
        keys.verify_security_proof(raw, &identity(), "", &[], NOW + 304)
            .is_ok()
    );
    assert_eq!(
        keys.verify_security_proof(raw, &identity(), "", &[], NOW + 305),
        Err(AuthError::Expired)
    );
    for field in 0..4 {
        let mut other = identity();
        match field {
            0 => other.user_id += 1,
            1 => other.sid.push('x'),
            2 => other.user_auth_version += 1,
            _ => other.session_version += 1,
        }
        assert_eq!(
            keys.verify_security_proof(raw, &other, "", &[], NOW),
            Err(AuthError::Invalid)
        );
    }
    assert!(matches!(
        keys.parse_dashboard_access(raw, NOW),
        DashboardAccess::Internal(Err(AuthError::Invalid))
    ));
    let access = keys.issue_access_with_jti(&identity(), NOW, JTI).unwrap();
    assert!(
        keys.verify_security_proof(access.token.expose_secret(), &identity(), "", &[], NOW)
            .is_err()
    );
    assert!(
        keys.issue_security_proof_with_jti(&identity(), " ", &scopes, NOW, JTI)
            .is_err()
    );
    assert!(
        keys.issue_security_proof_with_jti(&identity(), "totp", &[], NOW, JTI)
            .is_err()
    );
}

#[test]
fn internal_jwt_failure_never_becomes_opaque() {
    let keys = AuthKeys::new(SECRET);
    let raw = sign(&claims(), "security_proof", "HS256");
    assert!(matches!(
        keys.parse_dashboard_access(&raw, NOW),
        DashboardAccess::Internal(Err(_))
    ));
    let mut malformed = claims();
    malformed["uv"] = json!("bad-type");
    assert!(matches!(
        keys.parse_dashboard_access(&sign(&malformed, "access", "HS256"), NOW),
        DashboardAccess::Internal(Err(_))
    ));
    assert!(matches!(
        keys.parse_dashboard_access(&sign(&claims(), "access", "HS256"), NOW + 905),
        DashboardAccess::Internal(Err(AuthError::Expired))
    ));
    assert!(matches!(
        keys.parse_dashboard_access("opaque-api-key", NOW),
        DashboardAccess::Opaque
    ));
}

#[test]
fn refresh_exact_bytes_deterministic_rotation_and_uuid_forms() {
    let keys = AuthKeys::new(SECRET);
    let credential = RefreshCredential::parse(&format!(" \t{SID}.current-secret\n")).unwrap();
    assert_eq!(credential.sid(), SID);
    let key = hmac(SECRET.as_bytes(), b"new-api/auth/refresh/v1");
    let expected = lowerhex(&hmac(&key, b"current-secret"));
    assert!(keys.refresh_hash(credential.secret()).expose_secret() == expected);
    assert!(keys.matches_refresh_hash(credential.secret(), &format!("{expected}  ")));
    assert!(!keys.matches_refresh_hash("wrong", &expected));
    let rotate_key = hmac(SECRET.as_bytes(), b"new-api/auth/refresh-rotate/v1");
    let expected_next = lowerhex(&hmac(
        &rotate_key,
        format!("{SID}.current-secret").as_bytes(),
    ));
    let next = keys.next_refresh(&credential);
    assert!(next.secret() == expected_next);
    assert!(next.raw().expose_secret() == keys.next_refresh(&credential).raw().expose_secret());
    assert!(!keys.matches_refresh_hash(next.secret(), &expected));
    for sid in [
        SID.to_owned(),
        SID.to_uppercase(),
        SID.replace('-', ""),
        format!("{{{SID}}}"),
        format!("URN:UUID:{SID}"),
    ] {
        let parsed = RefreshCredential::parse(&format!("{sid}.s")).unwrap();
        assert_eq!(parsed.sid(), sid);
    }
    for raw in [
        format!("{SID}."),
        format!("{SID}.a.b"),
        "session-1.secret".to_owned(),
        SID.to_owned(),
        String::new(),
    ] {
        assert!(RefreshCredential::parse(&raw).is_err());
    }
}

#[test]
fn production_randomness_has_required_shape() {
    let a = RefreshCredential::generate().unwrap();
    let b = RefreshCredential::generate().unwrap();
    assert!(a.raw().expose_secret() != b.raw().expose_secret());
    assert_eq!(a.secret().len(), 64);
    assert!(a.secret().bytes().all(|b| b.is_ascii_alphanumeric()));
    assert_eq!(uuid::Uuid::parse_str(a.sid()).unwrap().get_version_num(), 4);
    let issued = AuthKeys::new(SECRET)
        .issue_access(&identity(), NOW)
        .unwrap();
    let payload = issued.token.expose_secret().split('.').nth(1).unwrap();
    let value: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(
        uuid::Uuid::parse_str(value["jti"].as_str().unwrap())
            .unwrap()
            .get_version_num(),
        4
    );
}

// 以下测试只消费独立 Go 进程产生的期望，缺少 fixture 在任何环境都失败。
#[derive(serde::Deserialize)]
struct CryptoOracle {
    schema: u32,
    session_secret: String,
    now: i64,
    jti: String,
    generation: Vec<GoGeneration>,
    verification: Vec<GoVerification>,
    derived: std::collections::BTreeMap<String, String>,
    refresh: Vec<GoRefresh>,
    tokens: Vec<GoToken>,
}

#[derive(serde::Deserialize)]
struct GoGeneration {
    password_hex: String,
    too_long: bool,
    hash: String,
    salt_hex: String,
}

#[derive(serde::Deserialize)]
struct GoVerification {
    name: String,
    password_hex: String,
    hash: String,
    valid: bool,
}

#[derive(serde::Deserialize)]
struct GoRefresh {
    raw: String,
    valid: bool,
    sid: String,
    secret: String,
    hash: String,
    next: String,
    next_hash: String,
}

#[derive(serde::Deserialize)]
struct GoToken {
    name: String,
    raw: String,
    purpose: String,
    now: i64,
    status: String,
    internal: bool,
    exact: bool,
    sid: String,
}

fn oracle() -> CryptoOracle {
    let path = std::env::var_os("P2_CRYPTO_ORACLE_PATH")
        .expect("P2_CRYPTO_ORACLE_PATH is required; generate the Go oracle in Actions");
    let bytes = std::fs::read(path).expect("cannot read the Go crypto oracle");
    let oracle: CryptoOracle = serde_json::from_slice(&bytes).expect("invalid Go crypto oracle");
    assert_eq!(oracle.schema, 1);
    assert!(oracle.session_secret == SECRET);
    assert_eq!(oracle.now, NOW);
    assert_eq!(oracle.jti, JTI);
    assert_eq!(oracle.generation.len(), 8);
    assert!(oracle.verification.len() >= 30);
    assert_eq!(oracle.derived.len(), 4);
    assert!(oracle.refresh.len() >= 13);
    assert!(oracle.tokens.len() >= 30);
    oracle
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("oracle hex must be ASCII");
            u8::from_str_radix(pair, 16).expect("invalid oracle hex")
        })
        .collect()
}

#[test]
fn go_oracle_password_generation_and_verification() {
    let oracle = oracle();
    for case in oracle.generation {
        let password = unhex(&case.password_hex);
        if case.too_long {
            assert!(matches!(
                hash_password_with_salt(&password, [0; 16]),
                Err(AuthError::PasswordTooLong)
            ));
        } else {
            let salt: [u8; 16] = unhex(&case.salt_hex).try_into().unwrap();
            let actual = hash_password_with_salt(&password, salt).unwrap();
            assert!(actual.expose_secret() == case.hash);
        }
    }
    for case in oracle.verification {
        let actual = verify_password(&unhex(&case.password_hex), &case.hash).unwrap();
        assert_eq!(actual, case.valid, "Go bcrypt case: {}", case.name);
    }
}

#[test]
fn go_oracle_derivation_refresh_and_uuid_variants() {
    let oracle = oracle();
    let keys = AuthKeys::new(&oracle.session_secret);
    // 独立 Go 期望验证派生公式；生产 access/proof 密钥还由 JWT 精确比较覆盖。
    for (purpose, expected) in oracle.derived {
        let actual = hmac(
            oracle.session_secret.as_bytes(),
            format!("new-api/auth/{purpose}/v1").as_bytes(),
        );
        assert!(lowerhex(&actual) == expected);
    }
    for case in oracle.refresh {
        let parsed = RefreshCredential::parse(&case.raw);
        assert_eq!(parsed.is_ok(), case.valid);
        if !case.valid {
            continue;
        }
        let credential = parsed.unwrap();
        assert_eq!(credential.sid(), case.sid);
        assert!(credential.secret() == case.secret);
        assert!(keys.refresh_hash(credential.secret()).expose_secret() == case.hash);
        assert!(keys.matches_refresh_hash(credential.secret(), &case.hash));
        let next = keys.next_refresh(&credential);
        assert_eq!(next.sid(), case.sid);
        assert!(next.secret() == case.next);
        assert!(keys.refresh_hash(next.secret()).expose_secret() == case.next_hash);
    }
}

#[test]
fn go_oracle_jwt_exact_bytes_verification_and_no_fallback() {
    let oracle = oracle();
    let keys = AuthKeys::new(&oracle.session_secret);
    for case in oracle.tokens {
        let mut who = identity();
        who.sid = case.sid.clone();
        let result = match case.purpose.as_str() {
            "access" => keys.parse_access(&case.raw, case.now).map(|actual| {
                assert_eq!(actual, who);
            }),
            "security_proof" => keys
                .verify_security_proof(&case.raw, &who, "password:update", &[], case.now)
                .map(|method| assert_eq!(method, "totp")),
            _ => panic!("unexpected oracle purpose"),
        };
        let status = match result {
            Ok(()) => "ok",
            Err(AuthError::Expired) => "expired",
            Err(AuthError::Invalid) => "invalid",
            Err(_) => "other",
        };
        assert_eq!(status, case.status, "Go JWT case: {}", case.name);
        let internal = classify_dashboard(&case.raw) == CredentialKind::InternalDashboard;
        assert_eq!(internal, case.internal, "Go classification: {}", case.name);
        if internal {
            assert!(matches!(
                keys.parse_dashboard_access(&case.raw, case.now),
                DashboardAccess::Internal(_)
            ));
        }
        if case.exact {
            let issued = if case.purpose == "access" {
                keys.issue_access_with_jti(&who, oracle.now, &oracle.jti)
            } else {
                keys.issue_security_proof_with_jti(
                    &who,
                    "totp",
                    &["password:update".to_owned()],
                    oracle.now,
                    &oracle.jti,
                )
            }
            .unwrap();
            assert!(issued.token.expose_secret() == case.raw);
        }
    }
}
