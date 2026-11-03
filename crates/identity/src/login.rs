//! 登录密码验证边界；成功仅代表密码匹配，不授予访问权限。
use crate::AuthError;

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
