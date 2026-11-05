//! 登录密码验证边界；成功仅代表密码匹配，不授予访问权限。
pub mod orchestrate;

use crate::{
    AuthError,
    users::{LoginCredential, LoginCredentialRepository},
};

/// 仅保留固定分类，不携带密码、hash 或底层错误。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginError {
    InvalidPassword,
    PasswordTooLong,
    Storage,
}

impl From<AuthError> for LoginError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::Invalid => Self::InvalidPassword,
            AuthError::PasswordTooLong => Self::PasswordTooLong,
            _ => Self::Storage,
        }
    }
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPassword => f.write_str("invalid password"),
            Self::PasswordTooLong => std::fmt::Display::fmt(&AuthError::PasswordTooLong, f),
            Self::Storage => f.write_str("login credential storage error"),
        }
    }
}

impl std::error::Error for LoginError {}

/// 按 UTF-8 字节限制 bcrypt 输入，不裁剪、截断或规范化密码。
/// 无法解析的存储 hash 归为 Storage，且不传播 bcrypt 错误文本。
pub fn verify_password(password: &str, stored_hash: &str) -> Result<(), LoginError> {
    if password.len() > 72 {
        return Err(AuthError::PasswordTooLong.into());
    }
    match bcrypt::verify(password, stored_hash) {
        Ok(true) => Ok(()),
        Ok(false) => Err(LoginError::InvalidPassword),
        Err(_) => Err(LoginError::Storage),
    }
}

pub const USER_STATUS_ENABLED: i64 = 1;

/// 与 Go `ValidateAndFill` 分类一致：空输入、凭据不匹配、存储故障。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginCredentialError {
    EmptyCredentials,
    InvalidCredentials,
    Storage,
}

/// 校验成功后的最小身份，登录 handler 仍需完成 2FA 与会话签发。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedLogin {
    pub user_id: i64,
    pub username: String,
    pub auth_version: i64,
}

/// 按 Go 顺序校验：空 password hash 不匹配、bcrypt 失败一律不匹配、未启用账号不匹配。
pub fn check_credential(
    credential: &LoginCredential,
    password: &str,
) -> Result<AuthenticatedLogin, LoginCredentialError> {
    if credential.password_hash.is_empty() {
        return Err(LoginCredentialError::InvalidCredentials);
    }
    // Go's ValidatePasswordAndHash returns false for every bcrypt error,
    // including a malformed stored hash, so none of them is a storage error.
    if verify_password(password, &credential.password_hash).is_err() {
        return Err(LoginCredentialError::InvalidCredentials);
    }
    if credential.status != USER_STATUS_ENABLED {
        return Err(LoginCredentialError::InvalidCredentials);
    }
    Ok(AuthenticatedLogin {
        user_id: credential.user_id,
        username: credential.username.clone(),
        auth_version: credential.auth_version,
    })
}

/// Port of `User.ValidateAndFill`: trim the login name, look up by username or
/// email, then run the credential check. A database failure stays distinct so
/// the handler can answer with the database error category.
pub async fn validate_and_fill(
    repository: &LoginCredentialRepository,
    username: &str,
    password: &str,
) -> Result<AuthenticatedLogin, LoginCredentialError> {
    let username = username.trim();
    if username.is_empty() || password.is_empty() {
        return Err(LoginCredentialError::EmptyCredentials);
    }
    let credential = repository
        .by_username_or_email(username)
        .await
        .map_err(|_| LoginCredentialError::Storage)?
        .ok_or(LoginCredentialError::InvalidCredentials)?;
    check_credential(&credential, password)
}
