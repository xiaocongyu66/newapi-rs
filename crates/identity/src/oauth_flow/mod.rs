//! 内置 OAuth 提供商登录 / 绑定与微信、Telegram、邮箱绑定流程：
//! Go `transport/handler/handle_oauth.go`（state 与 `HandleOAuth` 编排）、
//! `identity/bind_wechat.go`、`identity/bind_telegram.go`、
//! `identity/manage_users.go` 的 `EmailBind`、`identity/run_authflow.go`
//! （purpose 常量、断言防重放）与 `identity/claim_external_identity.go`。
//!
//! 本 crate 提供三块能力，HTTP 编排在 `apps/server/src/oauth_http.rs`：
//!
//! 1. [`repository`]：`auth_flows` 的 OAuth/Telegram 用法——与既有
//!    [`crate::auth_flow`] 仓储同行同源（同一 HMAC key、同一 token 格式），
//!    但额外携带 Go 模型的 `provider` / `intent` 两个可空列；2FA/passkey
//!    切片不使用它们，因此不修改那个仓储。
//! 2. [`telegram`]：Telegram Login Widget 的 `hash` 校验（HMAC-SHA256，
//!    secret = SHA256(bot token)）与断言防重放的时间窗计算，纯函数。
//! 3. [`providers`] + [`store`] + [`settings`]：提供商的 token 交换与
//!    用户信息拉取（出站传输可注入）、用户的查找/创建/绑定列更新、
//!    options 表上的 OAuth 开关与密钥快照。
//!
//! ## 安全要点（逐字对 Go）
//!
//! - state 是 32 字节 CSPRNG token，库中只存 HMAC-SHA256 摘要
//!   （key = `auth-flow-v1:` + session secret）；TTL 10 分钟，消费走
//!   条件 UPDATE，单次有效，且登录/绑定 intent、provider 与会话引用
//!   都参与匹配，token 不能跨用途重放。
//! - 绑定 intent 的 flow 在回调侧必须携带创建它的同一个浏览器会话
//!   （user_id + session_id 双匹配）。
//! - Telegram 断言（`hash` 值）在登录与绑定的同一事务内落
//!   `auth_flows`（purpose=`telegram_assertion`，token_hash =
//!   HMAC("external:"+purpose+":"+hash)），唯一索引保证重放拒绝是
//!   原子的；登录还叠加 `auth_date` 的 5 分钟过期 / 2 分钟未来偏移。
//! - 绑定列更新只写单列（Go `UpdateUserBindColumn` 的白名单约束），
//!   绝不把读取时刻的用户快照整体写回。
//!
//! ## 时间约定
//!
//! 与 [`crate::auth_flow`] 一致：调用方传 Unix 秒；SQL 中以数据库时间戳
//! 表达 `expires_at`/`consumed_at`/`created_at`（auth_flows 列是 datetime/
//! TIMESTAMPTZ），其余 bigint 列直接绑定整数。

pub mod providers;
pub mod repository;
pub mod settings;
pub mod store;
pub mod telegram;

/// Go `AuthFlowPurposeOAuth`（`run_authflow.go:19`）。
pub const PURPOSE_OAUTH: &str = "oauth";
/// Go `AuthFlowPurposeTelegramBind`（`run_authflow.go:24`）。
pub const PURPOSE_TELEGRAM_BIND: &str = "telegram_bind";
/// Go `AuthFlowPurposeTelegramAssertion`（`run_authflow.go:25`）。
pub const PURPOSE_TELEGRAM_ASSERTION: &str = "telegram_assertion";
/// Go `AuthFlowIntentLogin` / `AuthFlowIntentBind`（`run_authflow.go:26-27`）。
pub const INTENT_LOGIN: &str = "login";
pub const INTENT_BIND: &str = "bind";

/// Go `oauthAuthFlowTTL`（`handle_oauth.go:21`）：10 分钟。
pub const OAUTH_FLOW_TTL_SECONDS: i64 = 600;
/// Go `telegramBindFlowTTL`（`bind_telegram.go:28`）：5 分钟。
pub const TELEGRAM_BIND_TTL_SECONDS: i64 = 300;
/// Go `telegramAuthorizationMaxAge`：签名断言的最长寿命。
pub const TELEGRAM_AUTHORIZATION_MAX_AGE: i64 = 300;
/// Go `telegramAuthorizationFutureSkew`：允许的未来偏移。
pub const TELEGRAM_AUTHORIZATION_FUTURE_SKEW: i64 = 120;

/// Telegram 绑定/登录的固定错误分类（Go `bind_telegram.go:30-37` 的
/// `TELEGRAM_BIND_*` 错误码 + 登录侧的文案分类）。不携带任何底层文本。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TelegramFlowError {
    /// 功能开关关闭（HTTP 层单独处理，不进该分类）。
    Disabled,
    /// 签名校验失败、参数缺失或断言已过期。
    InvalidRequest,
    /// flow 不存在、已消费或过期。
    FlowInvalid,
    /// 创建 flow 的会话已失效（含会话被撤销、auth_version 漂移）。
    SessionInvalid,
    /// Telegram 账号已绑定到某用户。
    AlreadyBound,
    /// 用户行不存在（软删除后按 Go 视为不存在）。
    UserDeleted,
    /// 用户被封禁。
    UserDisabled,
    /// 断言已被使用（仅登录侧：HTTP 403 分支）。
    AssertionReplayed,
    /// 数据库故障；客户端只见固定分类。
    Storage,
}

impl std::fmt::Display for TelegramFlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Disabled => "telegram oauth is disabled",
            Self::InvalidRequest => "telegram authorization is invalid",
            Self::FlowInvalid => "telegram bind flow is invalid",
            Self::SessionInvalid => "telegram bind session is invalid",
            Self::AlreadyBound => "telegram account is already bound",
            Self::UserDeleted => "telegram bind user was deleted",
            Self::UserDisabled => "telegram bind user is disabled",
            Self::AssertionReplayed => "telegram authorization has been used",
            Self::Storage => "telegram flow storage failure",
        })
    }
}

impl std::error::Error for TelegramFlowError {}

impl From<sqlx::Error> for TelegramFlowError {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}

/// `GET /api/oauth/:provider` 登录/绑定编排的固定错误分类。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OAuthFlowError {
    /// provider 不在注册集合（内置四个或 custom_oauth_providers 行）。
    UnknownProvider,
    /// state 无效、已消费或过期。
    StateInvalid,
    /// 提供商存在但未启用（i18n `oauth.not_enabled`）。
    NotEnabled,
    /// 上游 token / 用户信息失败；`key` 是固定 i18n 键（oauth.*），
    /// 由 HTTP 层翻译；Go 的 AccessDenied 直传文案走 [`Self::Message`]。
    Provider { key: &'static str, provider: String },
    /// LinuxDO 信任等级不足（i18n `oauth.trust_level_low`）。
    TrustLevel,
    /// 提供商直接给出的拒绝文案（Go `AccessDeniedError.Message`）。
    Message(String),
    /// 注册关闭（i18n `user.register_disabled`）。
    RegistrationDisabled,
    /// OAuth 用户行已被软删（i18n `oauth.user_deleted`）。
    UserDeleted,
    /// 新用户邮箱被占用（i18n `user.email_already_taken`）。
    EmailTaken,
    /// 账号被封禁（i18n `oauth.user_banned`）。
    UserBanned,
    /// 目标 OAuth 账号已被绑定（i18n `oauth.already_bound`）。
    AlreadyBound { provider: String },
    /// 数据库故障；客户端只见固定分类。
    Storage,
}

impl std::fmt::Display for OAuthFlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("oauth flow failed")
    }
}

impl std::error::Error for OAuthFlowError {}

impl From<sqlx::Error> for OAuthFlowError {
    fn from(_: sqlx::Error) -> Self {
        Self::Storage
    }
}
