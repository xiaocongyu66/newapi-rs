//! 密码与刷新凭证；只组合成熟密码学库，不实现密码学原语。
use base64::{Engine, alphabet, engine::general_purpose};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::{Builder, Uuid};

use crate::{AuthError, SecretString};

pub(crate) type HmacSha256 = Hmac<Sha256>;

pub(crate) fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    // HMAC 接受任意长度密钥，构造失败不可达。
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length is unrestricted");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub(crate) fn equal(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

pub fn hash_password(password: &[u8]) -> Result<SecretString, AuthError> {
    if password.len() > 72 {
        return Err(AuthError::PasswordTooLong);
    }
    let mut salt = [0; 16];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| AuthError::Internal)?;
    hash_password_with_salt(password, salt)
}

/// 固定盐仅供差分测试；生产调用 hash_password。
pub fn hash_password_with_salt(
    password: &[u8],
    salt: [u8; 16],
) -> Result<SecretString, AuthError> {
    if password.len() > 72 {
        return Err(AuthError::PasswordTooLong);
    }
    bcrypt::hash_with_salt(password, 10, salt)
        .map(|parts| SecretString::new(parts.format_for_version(bcrypt::Version::TwoA)))
        .map_err(|_| AuthError::Internal)
}

/// Go 校验允许长输入，bcrypt 只使用前 72 字节；不裁剪空格或 NUL。
/// Go 的版本解码允许无 minor 版本以及不高于字符 '2' 的 major。
pub fn verify_password(password: &[u8], stored: &str) -> Result<bool, AuthError> {
    let bytes = stored.as_bytes();
    if bytes.len() < 59 || bytes[0] != b'$' || bytes[1] > b'2' {
        return Ok(false);
    }
    let start = if bytes[2] == b'$' { 3 } else { 4 };
    if bytes.len() != start + 56 {
        return Ok(false);
    }
    let cost = match std::str::from_utf8(&bytes[start..start + 2])
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
    {
        Some(cost @ 4..=31) => cost,
        _ => return Ok(false),
    };
    // Go 的标准 base64 解码允许最后未使用位非零。
    let engine = general_purpose::GeneralPurpose::new(
        &alphabet::BCRYPT,
        general_purpose::NO_PAD.with_decode_allow_trailing_bits(true),
    );
    let salt: [u8; 16] = match engine.decode(&bytes[start + 3..start + 25]) {
        Ok(salt) => match salt.try_into() {
            Ok(salt) => salt,
            Err(_) => return Ok(false),
        },
        Err(_) => return Ok(false),
    };
    let generated = bcrypt::hash_with_salt(&password[..password.len().min(72)], cost, salt)
        .map_err(|_| AuthError::Internal)?
        .format_for_version(bcrypt::Version::TwoA);
    Ok(equal(&generated.as_bytes()[29..], &bytes[start + 25..]))
}

pub(crate) fn random_uuid() -> Result<String, AuthError> {
    let mut bytes = [0; 16];
    OsRng.try_fill_bytes(&mut bytes).map_err(|_| AuthError::Internal)?;
    Ok(Builder::from_random_bytes(bytes).into_uuid().to_string())
}

/// 包装派生密钥，避免 Debug/Serialize 暴露。
pub struct AuthKeys {
    pub(crate) access: [u8; 32],
    pub(crate) proof: [u8; 32],
    refresh: [u8; 32],
    rotate: [u8; 32],
}

impl AuthKeys {
    pub fn new(session_secret: &str) -> Self {
        let derive = |purpose: &str| {
            mac(session_secret.as_bytes(), format!("new-api/auth/{purpose}/v1").as_bytes())
        };
        Self {
            access: derive("access"),
            proof: derive("security_proof"),
            refresh: derive("refresh"),
            rotate: derive("refresh-rotate"),
        }
    }

    pub fn refresh_hash(&self, secret: &str) -> SecretString {
        SecretString::new(hex(&mac(&self.refresh, secret.as_bytes())))
    }

    pub fn matches_refresh_hash(&self, secret: &str, stored: &str) -> bool {
        equal(self.refresh_hash(secret).expose_secret().as_bytes(), stored.trim().as_bytes())
    }

    pub fn next_refresh(&self, credential: &RefreshCredential) -> RefreshCredential {
        let secret = hex(&mac(&self.rotate, credential.raw().expose_secret().as_bytes()));
        RefreshCredential { sid: credential.sid.clone(), secret: SecretString::new(secret) }
    }
}

pub struct RefreshCredential {
    sid: String,
    secret: SecretString,
}

impl RefreshCredential {
    pub fn generate() -> Result<Self, AuthError> {
        const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut secret = String::with_capacity(64);
        while secret.len() < 64 {
            let mut byte = [0];
            OsRng.try_fill_bytes(&mut byte).map_err(|_| AuthError::Internal)?;
            // 拒绝抽样避免取模偏差，248 为 62 的最大单字节倍数。
            if byte[0] < 248 {
                secret.push(ALPHABET[(byte[0] % 62) as usize] as char);
            }
        }
        Ok(Self { sid: random_uuid()?, secret: SecretString::new(secret) })
    }

    pub fn parse(raw: &str) -> Result<Self, AuthError> {
        let (sid, secret) = raw.trim().split_once('.').ok_or(AuthError::Invalid)?;
        if secret.is_empty() || secret.contains('.') || !go_uuid_valid(sid) {
            return Err(AuthError::Invalid);
        }
        // 不规范化 SID：轮换 HMAC 必须保留呈现的原始字节。
        Ok(Self { sid: sid.to_owned(), secret: SecretString::new(secret.to_owned()) })
    }

    pub fn sid(&self) -> &str { &self.sid }

    pub fn secret(&self) -> &str { self.secret.expose_secret() }

    pub fn raw(&self) -> SecretString {
        SecretString::new(format!("{}.{}", self.sid, self.secret.expose_secret()))
    }
}

fn go_uuid_valid(sid: &str) -> bool {
    // google/uuid 接受大小写 URN 前缀与 38 字节包裹形式；包裹字符不检查。
    let bytes = sid.as_bytes();
    let core = match bytes.len() {
        32 | 36 => sid,
        45 if bytes[..9].eq_ignore_ascii_case(b"urn:uuid:") => &sid[9..],
        38 => match std::str::from_utf8(&bytes[1..37]) {
            Ok(core) => core,
            Err(_) => return false,
        },
        _ => return false,
    };
    Uuid::parse_str(core).is_ok()
}
