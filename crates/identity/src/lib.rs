//! 身份纯算法边界；验签成功后仍须查询会话和当前用户状态。
#![forbid(unsafe_code)]

pub mod auth_session;
pub mod crypto;
pub mod login;
pub mod policy;
pub mod self_user;
pub mod session_cache;
pub mod sessions;
pub mod setup;
pub mod tokens;
pub mod user_auth;
pub mod users;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthIdentity {
    pub user_id: i64,
    pub sid: String,
    pub user_auth_version: i64,
    pub session_version: i64,
}

impl AuthIdentity {
    pub(crate) fn validate(&self) -> Result<(), AuthError> {
        if self.user_id <= 0
            || self.sid.is_empty()
            || self.user_auth_version <= 0
            || self.session_version <= 0
        {
            return Err(AuthError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialKind {
    Opaque,
    InternalDashboard,
}

/// 不携带原始凭证、第三方错误或数据库文本。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    Invalid,
    Expired,
    ProofScope,
    ProofMethod,
    PasswordTooLong,
    Internal,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "authentication credential is invalid",
            Self::Expired => "authentication token has expired",
            Self::ProofScope => "security proof scope mismatch",
            Self::ProofMethod => "security proof method mismatch",
            Self::PasswordTooLong => "password exceeds bcrypt byte limit",
            Self::Internal => "authentication internal error",
        })
    }
}

impl std::error::Error for AuthError {}

/// 仅显式暴露秘密；禁止派生 Debug 或 Serialize。
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}
