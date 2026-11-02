//! JWT 编码与用途隔离；时间由调用方注入，禁止读取隐式系统时钟。
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::Mac;
use serde::{Deserialize, Serialize};

use crate::crypto::{AuthKeys, HmacSha256, equal, mac, random_uuid};
use crate::{AuthError, AuthIdentity, CredentialKind, SecretString};

pub const ACCESS_TTL: i64 = 900;
pub const PROOF_TTL: i64 = 300;
pub const LEEWAY: i64 = 5;
const ISSUER: &str = "new-api";
const AUDIENCE: &str = "new-api-dashboard";

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn matches(&self) -> bool {
        match self {
            Self::One(value) => value == AUDIENCE,
            Self::Many(values) => values.iter().any(|value| value == AUDIENCE),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    token_use: String,
    sid: String,
    uv: i64,
    sv: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    method: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
    iss: String,
    sub: String,
    aud: Audience,
    exp: i64,
    nbf: i64,
    iat: i64,
    jti: String,
}

impl Claims {
    fn identity(&self) -> Result<AuthIdentity, AuthError> {
        let identity = AuthIdentity {
            user_id: self.sub.parse().map_err(|_| AuthError::Invalid)?,
            sid: self.sid.clone(),
            user_auth_version: self.uv,
            session_version: self.sv,
        };
        identity.validate()?;
        Ok(identity)
    }
}

/// token 原文不实现 Debug/Serialize，由 HTTP 层显式投影公开 access 字段。
pub struct IssuedToken {
    pub token: SecretString,
    pub expires_at: i64,
}

/// internal 分支内的失败必须终止认证，不得降级到 PAT/API key。
pub enum DashboardAccess {
    Opaque,
    Internal(Result<AuthIdentity, AuthError>),
}

impl AuthKeys {
    pub fn issue_access(&self, identity: &AuthIdentity, now: i64) -> Result<IssuedToken, AuthError> {
        self.issue_access_with_jti(identity, now, &random_uuid()?)
    }

    /// 固定 jti 仅用于差分测试；生产入口使用 CSPRNG UUIDv4。
    pub fn issue_access_with_jti(
        &self,
        identity: &AuthIdentity,
        now: i64,
        jti: &str,
    ) -> Result<IssuedToken, AuthError> {
        self.issue(identity, now, jti, None)
    }

    pub fn issue_security_proof(
        &self,
        identity: &AuthIdentity,
        method: &str,
        scopes: &[String],
        now: i64,
    ) -> Result<IssuedToken, AuthError> {
        self.issue_security_proof_with_jti(identity, method, scopes, now, &random_uuid()?)
    }

    pub fn issue_security_proof_with_jti(
        &self,
        identity: &AuthIdentity,
        method: &str,
        scopes: &[String],
        now: i64,
        jti: &str,
    ) -> Result<IssuedToken, AuthError> {
        self.issue(identity, now, jti, Some((method, scopes)))
    }

    fn issue(
        &self,
        identity: &AuthIdentity,
        now: i64,
        jti: &str,
        proof: Option<(&str, &[String])>,
    ) -> Result<IssuedToken, AuthError> {
        identity.validate()?;
        if jti.is_empty() {
            return Err(AuthError::Invalid);
        }
        let (purpose, key, ttl, method, scopes) = match proof {
            None => ("access", &self.access, ACCESS_TTL, "", &[][..]),
            Some((method, scopes)) if !method.trim().is_empty() && !scopes.is_empty() => {
                ("security_proof", &self.proof, PROOF_TTL, method.trim(), scopes)
            }
            Some(_) => return Err(AuthError::Invalid),
        };
        let expires_at = now.checked_add(ttl).ok_or(AuthError::Invalid)?;
        let claims = Claims {
            token_use: purpose.to_owned(),
            sid: identity.sid.clone(),
            uv: identity.user_auth_version,
            sv: identity.session_version,
            method: method.to_owned(),
            scopes: scopes.to_vec(),
            iss: ISSUER.to_owned(),
            sub: identity.user_id.to_string(),
            aud: Audience::Many(vec![AUDIENCE.to_owned()]),
            exp: expires_at,
            nbf: now.checked_sub(5).ok_or(AuthError::Invalid)?,
            iat: now,
            jti: jti.to_owned(),
        };
        // 与 Go encoding/json 默认 HTML 及行分隔符转义保持字节一致。
        let payload = serde_json::to_string(&claims)
            .map_err(|_| AuthError::Internal)?
            .replace('&', "\\u0026")
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029");
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(payload),
        );
        let signature = URL_SAFE_NO_PAD.encode(mac(key, input.as_bytes()));
        Ok(IssuedToken {
            token: SecretString::new(format!("{input}.{signature}")),
            expires_at,
        })
    }

    pub fn parse_access(&self, raw: &str, now: i64) -> Result<AuthIdentity, AuthError> {
        self.parse(raw, "access", &self.access, now)?.identity()
    }

    pub fn parse_dashboard_access(&self, raw: &str, now: i64) -> DashboardAccess {
        match classify_dashboard(raw) {
            CredentialKind::Opaque => DashboardAccess::Opaque,
            CredentialKind::InternalDashboard => DashboardAccess::Internal(self.parse_access(raw, now)),
        }
    }

    pub fn verify_security_proof(
        &self,
        raw: &str,
        identity: &AuthIdentity,
        required_scope: &str,
        allowed_methods: &[String],
        now: i64,
    ) -> Result<String, AuthError> {
        identity.validate()?;
        let claims = self.parse(raw, "security_proof", &self.proof, now)?;
        let actual = claims.identity()?;
        let bound = equal(&actual.user_id.to_be_bytes(), &identity.user_id.to_be_bytes())
            & equal(actual.sid.as_bytes(), identity.sid.as_bytes())
            & equal(&actual.user_auth_version.to_be_bytes(), &identity.user_auth_version.to_be_bytes())
            & equal(&actual.session_version.to_be_bytes(), &identity.session_version.to_be_bytes());
        if !bound || claims.method.is_empty() || claims.scopes.is_empty() {
            return Err(AuthError::Invalid);
        }
        let method_allowed = allowed_methods.iter().fold(allowed_methods.is_empty(), |found, method| {
            found | equal(method.as_bytes(), claims.method.as_bytes())
        });
        if !method_allowed {
            return Err(AuthError::ProofMethod);
        }
        let scope_allowed = claims.scopes.iter().fold(required_scope.is_empty(), |found, scope| {
            found | equal(scope.as_bytes(), required_scope.as_bytes())
        });
        if !scope_allowed {
            return Err(AuthError::ProofScope);
        }
        Ok(claims.method)
    }

    fn parse(&self, raw: &str, purpose: &str, key: &[u8], now: i64) -> Result<Claims, AuthError> {
        let (header, payload, signature, input) = segments(raw.trim()).ok_or(AuthError::Invalid)?;
        let header: serde_json::Value = decode_json(header)?;
        if header.get("alg").and_then(|v| v.as_str()) != Some("HS256") {
            return Err(AuthError::Invalid);
        }
        let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| AuthError::Invalid)?;
        let mut verifier = HmacSha256::new_from_slice(key).map_err(|_| AuthError::Internal)?;
        verifier.update(input.as_bytes());
        verifier.verify_slice(&signature).map_err(|_| AuthError::Invalid)?;
        // 必需字段缺失、null、类型不匹配或重复字段由强类型反序列化拒绝。
        let claims: Claims = decode_json(payload)?;
        if now as i128 >= claims.exp as i128 + LEEWAY as i128 {
            return Err(AuthError::Expired);
        }
        if claims.iss != ISSUER
            || !claims.aud.matches()
            || claims.token_use != purpose
            || claims.jti.is_empty()
            || claims.iat as i128 > now as i128 + LEEWAY as i128
            || claims.nbf as i128 > now as i128 + LEEWAY as i128
        {
            return Err(AuthError::Invalid);
        }
        claims.identity()?;
        Ok(claims)
    }
}

/// 分类不是认证；一旦识别内部标记，即使其他 claim 畸形也不降级。
pub fn classify_dashboard(raw: &str) -> CredentialKind {
    let Some((_, payload, _, _)) = segments(raw.trim()) else {
        return CredentialKind::Opaque;
    };
    let Ok(value) = decode_json::<serde_json::Value>(payload) else {
        return CredentialKind::Opaque;
    };
    let audience = value.get("aud");
    let matches_audience = audience.and_then(|v| v.as_str()) == Some(AUDIENCE)
        || audience.and_then(|v| v.as_array()).is_some_and(|values| {
            values.iter().any(|v| v.as_str() == Some(AUDIENCE))
        });
    if value.get("iss").and_then(|v| v.as_str()) == Some(ISSUER)
        && matches_audience
        && matches!(value.get("token_use").and_then(|v| v.as_str()), Some("access" | "security_proof"))
    {
        CredentialKind::InternalDashboard
    } else {
        CredentialKind::Opaque
    }
}

fn decode_json<T: serde::de::DeserializeOwned>(encoded: &str) -> Result<T, AuthError> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| AuthError::Invalid)?;
    serde_json::from_slice(&bytes).map_err(|_| AuthError::Invalid)
}

fn segments(raw: &str) -> Option<(&str, &str, &str, &str)> {
    let (input, signature) = raw.rsplit_once('.')?;
    let (header, payload) = input.split_once('.')?;
    if payload.contains('.') {
        return None;
    }
    Some((header, payload, signature, input))
}
