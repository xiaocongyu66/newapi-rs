//! 仪式状态在 `auth_flows` 上的存储：Go `passkey_session.go` 的移植。
//!
//! Go 把 `webauthn.SessionData` 连同 scope 序列化为 `flowPayload` 存入
//! `auth_flows.payload`，TTL 固定 5 分钟（`passkeyFlowTTL`），finish 时用
//! `ConsumeAuthFlow` 的条件更新单次消费。Rust 复用 `AuthFlowRepository`
//! 的 create/consume：payload 同样是 JSON，token 只以 HMAC 摘要落库。

use serde::{Deserialize, Serialize};

use crate::SecretString;
use crate::auth_flow::{AuthFlowError, AuthFlowMatch, AuthFlowRepository, CreateAuthFlow};
use crate::passkey::FLOW_TTL_SECONDS;

/// Go `flowPayload{SessionData, Scope}`；`session_data` 为 ceremony 状态 JSON。
#[derive(Clone, Serialize, Deserialize)]
struct FlowPayload {
    session_data: serde_json::Value,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    scope: String,
}

/// Go `errSessionNotFound`（消费失败、过期、已用、不可达统一归此）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionFlowError {
    NotFound,
    Storage,
}

impl std::fmt::Display for SessionFlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotFound => "Passkey 会话不存在或已过期",
            Self::Storage => "Passkey 会话存储失败",
        })
    }
}

impl std::error::Error for SessionFlowError {}

impl From<AuthFlowError> for SessionFlowError {
    fn from(error: AuthFlowError) -> Self {
        match error {
            AuthFlowError::Storage => Self::Storage,
            // Go 把 Invalid/Expired/Consumed 全部映射为 errSessionNotFound。
            AuthFlowError::Invalid | AuthFlowError::Expired | AuthFlowError::Consumed => {
                Self::NotFound
            }
        }
    }
}

/// Go `CreateSessionDataFlow`：状态为空即非法；返回原始 token 与过期 Unix 秒。
pub async fn create_session_data_flow(
    repository: &AuthFlowRepository,
    purpose: &str,
    user_id: i64,
    session_id: &str,
    scope: &str,
    state: &serde_json::Value,
    now: i64,
) -> Result<(SecretString, i64), SessionFlowError> {
    // Go 对 nil SessionData 返回“会话数据不能为空”；此处调用方只可能传入
    // 仪式产生的状态对象，非法输入会在 finish 反序列化时失败。
    let payload = serde_json::to_string(&FlowPayload {
        session_data: state.clone(),
        scope: scope.to_owned(),
    })
    .map_err(|_| SessionFlowError::Storage)?;
    let expires_at = now.saturating_add(FLOW_TTL_SECONDS);
    let (token, _) = repository
        .create(
            CreateAuthFlow {
                purpose: purpose.to_owned(),
                user_id,
                session_id: session_id.to_owned(),
                payload,
                expires_at,
            },
            now,
        )
        .await?;
    Ok((token, expires_at))
}

/// Go `PopSessionDataFlow`：消费成功返回 (状态 JSON, scope)。
pub async fn pop_session_data_flow(
    repository: &AuthFlowRepository,
    token: &str,
    purpose: &str,
    user_id: i64,
    session_id: &str,
    now: i64,
) -> Result<(serde_json::Value, String), SessionFlowError> {
    let flow = repository
        .consume(
            token,
            AuthFlowMatch {
                purpose,
                user_id,
                session_id,
            },
            now,
        )
        .await?;
    let payload: FlowPayload =
        serde_json::from_str(&flow.payload).map_err(|_| SessionFlowError::NotFound)?;
    Ok((payload.session_data, payload.scope))
}
