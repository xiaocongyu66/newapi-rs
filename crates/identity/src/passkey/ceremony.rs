//! WebAuthn 仪式封装：Go `wa.BeginRegistration` / `wa.CreateCredential` /
//! `wa.BeginDiscoverableLogin` / `wa.ValidatePasskeyLogin` / `wa.BeginLogin` /
//! `wa.ValidateLogin` 六个调用点的 safe wrapper 对应实现。
//!
//! 状态序列化依赖 `danger-allow-state-serialisation`（与 Go 的
//! `SessionData` JSON 等存），发现式登录依赖 `conditional-ui`。
//! learned divergences 记录在 `passkey/mod.rs` 模块注释。

use serde::Serialize;
use serde_json::Value;
use webauthn_rs::prelude::{
    AuthenticationResult, Credential, DiscoverableAuthentication, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, Uuid, Webauthn,
};

use crate::passkey::cose;

/// 仪式失败的固定分类；Go 经 `CtxApiError` 回复 go-webauthn 的英文文本，
/// Rust 不转述库错误，统一落固定文案（`passkey.verify_failed`）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyError {
    /// 库返回的校验失败或反序列化失败。
    Invalid,
    /// COSE 公钥无法在已知键型内编码/解码。
    Cose,
}

impl std::fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "Passkey 验证失败，请重试或联系管理员",
            Self::Cose => "Passkey 凭证格式无效",
        })
    }
}

impl std::error::Error for CeremonyError {}

impl From<webauthn_rs::prelude::WebauthnError> for CeremonyError {
    fn from(_: webauthn_rs::prelude::WebauthnError) -> Self {
        Self::Invalid
    }
}

impl From<cose::CoseError> for CeremonyError {
    fn from(error: cose::CoseError) -> Self {
        match error {
            cose::CoseError::Unsupported => Self::Cose,
            cose::CoseError::Invalid => Self::Invalid,
        }
    }
}

/// Go `WebAuthnUser` 的三个字段：ID、用户名、显示名。
pub struct CeremonyUser<'a> {
    pub id: i64,
    pub username: &'a str,
    pub display_name: &'a str,
}

impl CeremonyUser<'_> {
    /// Go `WebAuthnID`：用户 ID 的稳定字节。webauthn-rs 要求 16 字节 Uuid，
    /// 取 u128 大端（高 8 字节为零填充）；[`user_handle_to_user_id`] 按同
    /// 编码还原比对。
    pub fn unique_id(&self) -> Uuid {
        Uuid::from_bytes((self.id as u128).to_be_bytes())
    }

    /// Go `WebAuthnName`：trim 后为空回退 `user-<id>`。
    pub fn name(&self) -> String {
        let name = self.username.trim();
        if name.is_empty() {
            let id = self.id;
            format!("user-{id}")
        } else {
            name.to_owned()
        }
    }

    /// Go `WebAuthnDisplayName`：trim 后为空回退用户名。
    pub fn display_name(&self) -> String {
        let display = self.display_name.trim();
        if display.is_empty() {
            self.name()
        } else {
            display.to_owned()
        }
    }
}

/// 注册成功后需要落库的字段（Go `NewPasskeyCredentialFromWebAuthn` 的可
/// 持久化子集；attachment 由 HTTP 层从注册响应的顶层字段提取）。
#[derive(Clone, Debug)]
pub struct RegisteredCredential {
    pub credential_id: Vec<u8>,
    /// COSE 公钥的原始 CBOR 字节。
    pub public_key: Vec<u8>,
    /// attestation format 的字符串名（"none"/"packed"/...）。
    pub attestation_format: String,
    pub counter: u32,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Vec<String>,
}

pub struct Ceremony {
    webauthn: Webauthn,
}

impl Ceremony {
    pub fn new(webauthn: Webauthn) -> Self {
        Self { webauthn }
    }

    /// Go `wa.BeginRegistration(waUser, WithExclusions(...))`。
    pub fn begin_registration(
        &self,
        user: &CeremonyUser<'_>,
        exclude_credential_ids: Vec<Vec<u8>>,
    ) -> Result<(Value, PasskeyRegistration), CeremonyError> {
        let exclude = if exclude_credential_ids.is_empty() {
            None
        } else {
            Some(exclude_credential_ids)
        };
        let (ccr, state) = self.webauthn.start_passkey_registration(
            user.unique_id(),
            &user.name(),
            &user.display_name(),
            exclude,
        )?;
        Ok((
            serde_json::to_value(&ccr).map_err(|_| CeremonyError::Invalid)?,
            state,
        ))
    }

    /// Go `wa.CreateCredential(waUser, sessionData, parsedCredential)`。
    /// `credential` 是请求体里的原始 JSON（顶层 `authenticatorAttachment`
    /// 由调用方自行提取）；协议结构解析失败落固定分类。
    pub fn finish_registration(
        &self,
        credential: Value,
        state: &PasskeyRegistration,
    ) -> Result<RegisteredCredential, CeremonyError> {
        let parsed: RegisterPublicKeyCredential =
            serde_json::from_value(credential).map_err(|_| CeremonyError::Invalid)?;
        let passkey = self.webauthn.finish_passkey_registration(&parsed, state)?;
        let cred: Credential = passkey.into();
        let attestation_format = serde_json::to_value(&cred.attestation_format)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or("none".to_owned());
        let transports = cred
            .transports
            .map(|transports| transports.iter().map(|t| t.to_string()).collect())
            .unwrap_or_default();
        Ok(RegisteredCredential {
            credential_id: cred.cred_id,
            public_key: cose::encode_cose_key(&cred.cred)?,
            attestation_format,
            counter: cred.counter,
            user_verified: cred.user_verified,
            backup_eligible: cred.backup_eligible,
            backup_state: cred.backup_state,
            transports,
        })
    }

    /// Go `wa.BeginDiscoverableLogin()`。webauthn-rs 在 options JSON 中附加
    /// `mediation: "conditional"`（Go 不输出该字段，前端只取 `publicKey`）；
    /// 返回前剥离以对齐 Go 响应形状。
    pub fn begin_login_discoverable(
        &self,
    ) -> Result<(Value, DiscoverableAuthentication), CeremonyError> {
        let (rcr, state) = self.webauthn.start_discoverable_authentication()?;
        let mut options = serde_json::to_value(&rcr).map_err(|_| CeremonyError::Invalid)?;
        if let Some(map) = options.as_object_mut() {
            map.remove("mediation");
        }
        Ok((options, state))
    }

    /// Go `wa.ValidatePasskeyLogin(handler, sessionData, parsedCredential)` 的
    /// 校验部分。凭据查找（按 credential ID）与用户句柄比对由调用方完成
    /// （Go 的 handler 回调），此处只按存储凭据做断言验签。
    pub fn finish_login_discoverable(
        &self,
        credential: &Value,
        state: DiscoverableAuthentication,
        stored: &Credential,
    ) -> Result<AuthenticationResult, CeremonyError> {
        let parsed: PublicKeyCredential =
            serde_json::from_value(credential.clone()).map_err(|_| CeremonyError::Invalid)?;
        Ok(self
            .webauthn
            .finish_discoverable_authentication_v2(&parsed, state, stored)?)
    }

    /// Go `wa.BeginLogin(waUser)`：allowCredentials 即用户的已绑凭据。
    pub fn begin_verification(
        &self,
        stored: &Credential,
    ) -> Result<(Value, PasskeyAuthentication), CeremonyError> {
        let passkeys = vec![Passkey::from(stored.clone())];
        let (rcr, state) = self.webauthn.start_passkey_authentication(&passkeys)?;
        let options = serde_json::to_value(&rcr).map_err(|_| CeremonyError::Invalid)?;
        Ok((options, state))
    }

    /// Go `wa.ValidateLogin(waUser, sessionData, parsedCredential)`。
    pub fn finish_verification(
        &self,
        credential: &Value,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult, CeremonyError> {
        let parsed: PublicKeyCredential =
            serde_json::from_value(credential.clone()).map_err(|_| CeremonyError::Invalid)?;
        Ok(self
            .webauthn
            .finish_passkey_authentication(&parsed, state)?)
    }
}

/// 供 HTTP 层把状态序列化为 flow payload（`danger-allow-state-serialisation`
/// 开启后这些类型实现 Serialize）。
pub fn state_to_value<T: Serialize>(state: &T) -> Result<Value, CeremonyError> {
    serde_json::to_value(state).map_err(|_| CeremonyError::Invalid)
}

/// discoverable 断言回传的 userHandle 还原为用户 ID（[`CeremonyUser::unique_id`]
/// 的逆编码）。长度不是 16 字节即无法还原，返回 `None`——对齐 Go
/// `strconv.Atoi` 失败时只记日志、不拒绝断言的处理（比对由调用方做）。
pub fn user_handle_to_user_id(user_handle: &[u8]) -> Option<i64> {
    let bytes: [u8; 16] = user_handle.try_into().ok()?;
    Some(i64::from_be_bytes(bytes[8..16].try_into().ok()?))
}
