//! 一次性认证流程仓储（2FA pending flow 的存储基础）。
//!
//! 对齐 Go `identity/run_authflow.go`：数据库只保存 token 的 HMAC-SHA256
//! 摘要，原始 token 仅返回给调用方；查询与消费都必须绑定 purpose，消费使用
//! 条件更新保证同一 token 最多成功一次。
//!
//! 时间全部由调用方以 Unix 秒传入，本模块不读取系统时钟。Go 的
//! `time.Time` 列在本仓储中显式采用 `BIGINT` 秒表示，与其他 Rust 仓储的
//! Unix 秒约定一致；列名、可空性与索引仍按 schema-inventory 的 auth_flows
//! 定义，不新增列。

pub mod repository;
pub mod token;

pub use repository::AuthFlowRepository;
pub use token::{
    PURPOSE_TWO_FA_LOGIN, Purpose, TOKEN_BYTES, auth_flow_key, generate_token, token_hash,
};

/// 固定错误分类；不携带原始 token、数据库文本或 SQL。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthFlowError {
    /// token/purpose 为空、未匹配或输入不合法。
    Invalid,
    /// 流程已超过 `expires_at`。
    Expired,
    /// 流程已被消费，或条件更新未命中。
    Consumed,
    /// 数据库、连接池或 CSPRNG 失败。
    Storage,
}

impl std::fmt::Display for AuthFlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "auth flow is invalid",
            Self::Expired => "auth flow has expired",
            Self::Consumed => "auth flow has already been consumed",
            Self::Storage => "auth flow storage failure",
        })
    }
}

impl std::error::Error for AuthFlowError {}

impl From<sqlx::Error> for AuthFlowError {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}

/// `auth_flows` 的权威记录；不派生 Debug，避免 payload/session 绑定进入日志。
#[derive(Clone, PartialEq, Eq)]
pub struct AuthFlow {
    pub id: i64,
    pub token_hash: String,
    pub purpose: String,
    pub user_id: i64,
    pub session_id: String,
    pub payload: String,
    pub expires_at: i64,
    pub consumed_at: Option<i64>,
    pub created_at: i64,
}

/// 创建输入；purpose 校验时 trim，但按 Go 行为原样落库。
pub struct CreateAuthFlow {
    pub purpose: String,
    pub user_id: i64,
    pub session_id: String,
    pub payload: String,
    pub expires_at: i64,
}

/// 查询绑定；`user_id == 0` 与空 `session_id` 表示不追加该过滤条件。
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthFlowMatch<'a> {
    pub purpose: &'a str,
    pub user_id: i64,
    pub session_id: &'a str,
}

#[cfg(test)]
mod tests;
