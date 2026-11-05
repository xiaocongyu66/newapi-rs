//! 不透明 flow token 与 HMAC 摘要；只在内存中出现原始 token。
#![allow(non_upper_case_globals)]

use base64::{Engine, engine::general_purpose};
use rand::{RngCore, rngs::OsRng};

use super::AuthFlowError;
use crate::SecretString;
use crate::crypto::mac;

/// Go `AuthFlowTokenBytes`：32 字节 CSPRNG。
pub const TOKEN_BYTES: usize = 32;

/// Go `AuthFlowPurposeTwoFALogin`。
pub const PURPOSE_TWO_FA_LOGIN: &str = "2fa_login";

/// 用途命名空间；值必须与 Go 字节级一致。
pub struct Purpose;

impl Purpose {
    #[allow(non_upper_case_globals)]
    pub const TwoFALogin: &'static str = PURPOSE_TWO_FA_LOGIN;
}

/// 与 Go `[]byte("auth-flow-v1:" + common.SessionSecret)` 完全一致。
pub fn auth_flow_key(session_secret: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity("auth-flow-v1:".len() + session_secret.len());
    key.extend_from_slice(b"auth-flow-v1:");
    key.extend_from_slice(session_secret.as_bytes());
    key
}

/// 生成 32 字节随机 token，并使用 RawURL（无 padding）编码。
pub fn generate_token() -> Result<SecretString, AuthFlowError> {
    let mut bytes = [0u8; TOKEN_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AuthFlowError::Storage)?;
    Ok(SecretString::new(
        general_purpose::URL_SAFE_NO_PAD.encode(bytes),
    ))
}

/// 小写十六进制 HMAC-SHA256；与 Go `common.GenerateHMACWithKey` 一致。
pub fn token_hash(key: &[u8], token: &str) -> String {
    lower_hex(&mac(key, token.as_bytes()))
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}
