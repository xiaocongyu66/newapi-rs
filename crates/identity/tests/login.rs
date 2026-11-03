use newapi_identity::AuthError;
use newapi_identity::crypto::hash_password_with_salt;
use newapi_identity::login::{LoginError, verify_password};

#[test]
fn verifies_correct_and_rejects_wrong_password() {
    let password = "correct horse battery staple";
    let stored = hash_password_with_salt(password.as_bytes(), [7; 16])
        .unwrap()
        .expose_secret()
        .to_owned();

    assert_eq!(verify_password(password, &stored), Ok(()));
    assert_eq!(
        verify_password("incorrect horse battery staple", &stored),
        Err(LoginError::InvalidPassword)
    );
}

#[test]
fn malformed_hash_is_storage_error_without_bcrypt_details() {
    let password = "password-that-must-not-appear-in-errors";
    let hash = "$2b$10$malformed-hash-that-must-not-appear";
    let error = verify_password(password, hash).unwrap_err();

    assert_eq!(error, LoginError::Storage);
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(password));
    assert!(!rendered.contains(hash));
}

#[test]
fn enforces_bcrypt_byte_limit_and_unicode_boundary() {
    let password = "密".repeat(24); // 72 UTF-8 bytes, exactly at the bcrypt limit.
    let stored = hash_password_with_salt(password.as_bytes(), [8; 16])
        .unwrap()
        .expose_secret()
        .to_owned();
    assert_eq!(verify_password(&password, &stored), Ok(()));

    let too_long = "密".repeat(25); // 75 UTF-8 bytes.
    let error = verify_password(&too_long, &stored).unwrap_err();
    assert_eq!(error, LoginError::PasswordTooLong);
    assert_eq!(error, AuthError::PasswordTooLong.into());

    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(&too_long));
    assert!(!rendered.contains(&stored));
}

#[test]
fn preserves_unicode_and_nul_bytes_in_password() {
    let password = "前缀\0尾部 ";
    let stored = hash_password_with_salt(password.as_bytes(), [9; 16])
        .unwrap()
        .expose_secret()
        .to_owned();

    assert_eq!(verify_password(password, &stored), Ok(()));
    assert_eq!(
        verify_password("前缀\0尾部", &stored),
        Err(LoginError::InvalidPassword)
    );
}
