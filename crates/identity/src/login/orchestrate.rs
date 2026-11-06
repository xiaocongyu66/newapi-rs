//! 密码校验通过后的登录装配：Go `setupLoginAtAuthVersion` 的顺序复刻。
//!
//! Go 的 handler 同时做协议适配与编排；这里把编排收敛为本模块，HTTP 层只做
//! 状态码与响应形状。错误分类不携带数据库文本、会话材料或原始 token。

use std::sync::Arc;

use newapi_storage::Database;
use serde_json::{Value, json};

use crate::audit::record_login_log;
use crate::auth_flow::{AuthFlowMatch, AuthFlowRepository, CreateAuthFlow, PURPOSE_TWO_FA_LOGIN};
use crate::auth_session::{AuthFence, LoginInput, RefreshResult, SessionAuth, SessionAuthError};
use crate::login::{LoginCredentialError, LoginCredentialRepository, validate_and_fill};
use crate::policy::{CasbinRuleRepository, self_user_permissions};
use crate::self_user::{Permissions, QuotaDisplaySettings, SelfUser, SelfUserInput, assemble};
use crate::sessions::SessionError;
use crate::two_fa::{TwoFaError, TwoFaRepository};
use crate::users::{UserProfile, UserProfileRepository};
use crate::{SecretString, login};

/// Go 登录 pending 时长：`time.Now().Add(5 * time.Minute)`。
pub const PENDING_FLOW_SECONDS: i64 = 300;

/// Go handler 硬编码/固定分类的 i18n key（zh-CN 与 Go 原文逐字一致）。
pub const MSG_LOGIN_DISABLED: &str = "user.password_login_disabled";
pub const MSG_INVALID_PARAMS: &str = "common.invalid_params";
pub const MSG_DATABASE_ERROR: &str = "common.database_error";
pub const MSG_CREDENTIAL_ERROR: &str = "user.username_or_password_error";
pub const MSG_REQUIRE_2FA: &str = "user.require_2fa";
pub const MSG_USER_BANNED: &str = "auth.user_banned";
pub const MSG_USER_NOT_FOUND: &str = "user.not_exists";
pub const MSG_2FA_INVALID_REQUEST: &str = "twofa.invalid_request";
pub const MSG_2FA_FLOW_EXPIRED: &str = "twofa.flow_expired";
pub const MSG_2FA_USER_DISABLED: &str = "twofa.user_disabled";
pub const MSG_2FA_NOT_ENABLED: &str = "twofa.not_enabled";

/// 登录编排的失败分类；HTTP 层据此选择响应形状，不携带敏感文本。
#[derive(Clone, Debug, PartialEq)]
pub enum LoginFailure {
    /// 固定 i18n key（`auth.user_banned`、`user.not_exists` 等）。
    Message(&'static str),
    /// Go `writeAuthSessionError` 的会话错误。
    Session(SessionAuthError),
    /// Go 用 `err.Error()`/`CtxApiErrorI18n` 回复的存储故障。
    Storage,
}

/// 成功登录的响应材料：会话包 + SelfUser 所需资料；展示设置由 HTTP 层注入。
pub struct LoginSuccess {
    pub bundle: RefreshResult,
    pub profile: UserProfile,
    pub permissions: Permissions,
}

/// 登录/2FA 登录的响应分类；文案已按语言解析，HTTP 层只定型。
pub enum LoginResponse {
    Success(Box<LoginSuccess>),
    Pending2fa {
        message: String,
        flow_token: SecretString,
        expires_at: i64,
    },
    /// HTTP 200 `{success:false,message}`（Go `CtxApiError*` 形状）。
    Rejected {
        message: String,
    },
    /// Go `writeAuthSessionError`：`{success:false,code,message:StatusText}`。
    Session {
        status: u16,
        code: &'static str,
    },
}

/// Go `AuthSessionErrorCode` 中登录路径可达的 code；登录没有 SID/refresh
/// 相关分支，映射到其固定子集。
pub fn session_error_code(error: &SessionAuthError) -> (u16, &'static str) {
    match error {
        SessionAuthError::Unauthorized | SessionAuthError::RefreshInvalid => {
            (401, "AUTH_UNAUTHORIZED")
        }
        SessionAuthError::SessionRevoked => (401, "AUTH_SESSION_REVOKED"),
        SessionAuthError::SessionMismatch => (409, "AUTH_SESSION_MISMATCH"),
        SessionAuthError::Race => (409, "AUTH_REFRESH_RACE"),
        SessionAuthError::SessionIdRequired => (400, "AUTH_SESSION_ID_REQUIRED"),
        SessionAuthError::Fence => (500, "AUTH_INTERNAL_ERROR"),
        SessionAuthError::Storage(SessionError::ActiveLimit) => (409, "AUTH_SESSION_LIMIT"),
        SessionAuthError::Storage(SessionError::IssuanceLimit) => {
            (429, "AUTH_SESSION_ISSUANCE_LIMIT")
        }
        // Go `ErrLoginSessionInvalid` 落 default 分支：500 AUTH_INTERNAL_ERROR。
        SessionAuthError::Storage(_) | SessionAuthError::BatchFailed { .. } => {
            (500, "AUTH_INTERNAL_ERROR")
        }
    }
}

fn translate(lang: &str, key: &str) -> String {
    newapi_i18n::translate(lang, key, std::iter::empty::<(&str, &str)>())
}

fn rejected(key: &str, lang: &str) -> LoginResponse {
    LoginResponse::Rejected {
        message: translate(lang, key),
    }
}

fn twofa_error_category(error: &TwoFaError) -> &'static str {
    match error {
        TwoFaError::Unavailable => "storage",
        TwoFaError::AttemptsConflict => "conflict",
        _ => "invalid",
    }
}

/// 登录编排依赖；由 HTTP 层按请求从 `AppState` 构造（仓储均为廉价 Clone）。
pub struct LoginService {
    auth: Arc<SessionAuth<AuthFence>>,
    credentials: LoginCredentialRepository,
    profiles: UserProfileRepository,
    two_fa: TwoFaRepository,
    flow: AuthFlowRepository,
    policy: CasbinRuleRepository,
    db: Database,
}

impl LoginService {
    pub fn new(auth: Arc<SessionAuth<AuthFence>>, db: Database, flow_key: Vec<u8>) -> Self {
        Self {
            auth,
            credentials: LoginCredentialRepository::new(db.clone()),
            profiles: UserProfileRepository::new(db.clone()),
            two_fa: TwoFaRepository::new(db.clone()),
            flow: AuthFlowRepository::new(db.clone(), flow_key),
            policy: CasbinRuleRepository::new(db.clone()),
            db,
        }
    }

    /// Port of Go `Login`：开关 → 参数 → 凭据 → 2FA pending → `SetupLogin`。
    /// JSON 解析发生在 HTTP 层；本方法从"凭据字段为空即 invalid params"开始。
    #[allow(clippy::too_many_arguments)]
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        password_login_enabled: bool,
        lang: &str,
        ip: &str,
        user_agent: &str,
        now: i64,
    ) -> Result<LoginResponse, LoginFailure> {
        if !password_login_enabled {
            return Ok(rejected(MSG_LOGIN_DISABLED, lang));
        }
        let authenticated = match validate_and_fill(&self.credentials, username, password).await {
            Ok(authenticated) => authenticated,
            Err(LoginCredentialError::EmptyCredentials) => {
                return Ok(rejected(MSG_INVALID_PARAMS, lang));
            }
            Err(LoginCredentialError::InvalidCredentials) => {
                return Ok(rejected(MSG_CREDENTIAL_ERROR, lang));
            }
            Err(LoginCredentialError::Storage) => {
                // Go 记 SysLog 后返回 database_error；错误文本不落日志。
                tracing::warn!(
                    event = "login_credential_storage_error",
                    "login credential lookup failed"
                );
                return Ok(rejected(MSG_DATABASE_ERROR, lang));
            }
        };
        // Go `IsTwoFAEnabled`：读取失败即 database_error。
        let two_fa_enabled = match self.two_fa.by_user_id(authenticated.user_id).await {
            Ok(record) => record.is_some_and(|record| record.is_enabled),
            Err(error) => {
                tracing::warn!(
                    event = "login_twofa_storage_error",
                    category = twofa_error_category(&error),
                    "login 2FA status lookup failed"
                );
                return Ok(rejected(MSG_DATABASE_ERROR, lang));
            }
        };
        if two_fa_enabled {
            let expires_at = now + PENDING_FLOW_SECONDS;
            let payload = json!({ "auth_version": authenticated.auth_version }).to_string();
            let created = self
                .flow
                .create(
                    CreateAuthFlow {
                        purpose: PURPOSE_TWO_FA_LOGIN.to_owned(),
                        user_id: authenticated.user_id,
                        session_id: String::new(),
                        payload,
                        expires_at,
                    },
                    now,
                )
                .await;
            let (token, _) = match created {
                Ok(created) => created,
                // Go `CtxApiError(err)` 返回 err.Error()；Rust 不转述错误文本。
                Err(_) => {
                    tracing::warn!(
                        event = "login_auth_flow_storage_error",
                        "pending flow create failed"
                    );
                    return Err(LoginFailure::Storage);
                }
            };
            return Ok(LoginResponse::Pending2fa {
                message: translate(MSG_REQUIRE_2FA, lang),
                flow_token: token,
                expires_at,
            });
        }
        // Go `SetupLogin` → `setupLoginAtAuthVersion(user, 0, c)`：不校验版本。
        self.respond(
            self.complete(None, authenticated.user_id, "password", ip, user_agent, now)
                .await,
            lang,
        )
    }

    /// Port of Go `Verify2FALogin`：读 flow → 用户与 payload 校验 → 验证码
    /// 校验 → 消费 flow → `setupLoginAtAuthVersion`。验证码错误不消费 flow，
    /// 与 Go 的"先验证后消费"一致（同一 flow_token 可重试）。
    #[allow(clippy::too_many_arguments)]
    pub async fn login_with_2fa(
        &self,
        flow_token: &str,
        code: &str,
        lang: &str,
        ip: &str,
        user_agent: &str,
        now: i64,
    ) -> Result<LoginResponse, LoginFailure> {
        // Go `binding:"required"`：空 code 在绑定阶段即"参数错误"。
        if code.is_empty() {
            return Ok(rejected(MSG_2FA_INVALID_REQUEST, lang));
        }
        let read_match = AuthFlowMatch {
            purpose: PURPOSE_TWO_FA_LOGIN,
            user_id: 0,
            session_id: "",
        };
        let Ok(flow) = self.flow.get(flow_token, read_match, now).await else {
            return Ok(rejected(MSG_2FA_FLOW_EXPIRED, lang));
        };
        let profile = match self.profiles.by_id(flow.user_id).await {
            Ok(Some(profile)) => profile,
            // Go：GetUserById 失败（含 DB 错误与不存在）都是固定"用户不存在"。
            Ok(None) | Err(_) => return Ok(rejected(MSG_USER_NOT_FOUND, lang)),
        };
        if profile.status != login::USER_STATUS_ENABLED {
            return Ok(rejected(MSG_2FA_USER_DISABLED, lang));
        }
        // payload 的 auth_version 必须仍与当前用户一致（Go `<= 0` 或不等）。
        let Some(expected_auth_version) =
            payload_auth_version(&flow.payload).filter(|version| *version > 0)
        else {
            return Ok(rejected(MSG_2FA_FLOW_EXPIRED, lang));
        };
        if expected_auth_version != profile.auth_version {
            return Ok(rejected(MSG_2FA_FLOW_EXPIRED, lang));
        }
        match self.two_fa.by_user_id(profile.id).await {
            Ok(record) if record.is_some_and(|record| record.is_enabled) => {}
            Ok(_) => return Ok(rejected(MSG_2FA_NOT_ENABLED, lang)),
            Err(error) => {
                tracing::warn!(
                    event = "twofa_login_storage_error",
                    category = twofa_error_category(&error),
                    "2FA login status lookup failed"
                );
                return Ok(rejected(MSG_DATABASE_ERROR, lang));
            }
        }
        if let Err(error) = self.two_fa.validate_login_code(profile.id, code, now).await {
            // Go 把验证错误文本直接返回；Rust 经 locale 解析固定文案。
            return Ok(LoginResponse::Rejected {
                message: error.client_message(lang),
            });
        }
        // Go 消费失败 → "会话已过期"（验证码已验证但流程已失效）。
        let consume_match = AuthFlowMatch {
            purpose: PURPOSE_TWO_FA_LOGIN,
            user_id: profile.id,
            session_id: "",
        };
        if self
            .flow
            .consume(flow_token, consume_match, now)
            .await
            .is_err()
        {
            return Ok(rejected(MSG_2FA_FLOW_EXPIRED, lang));
        }
        self.respond(
            self.complete(
                Some(expected_auth_version),
                profile.id,
                "2fa",
                ip,
                user_agent,
                now,
            )
            .await,
            lang,
        )
    }

    fn respond(
        &self,
        outcome: Result<LoginSuccess, LoginFailure>,
        lang: &str,
    ) -> Result<LoginResponse, LoginFailure> {
        Ok(match outcome {
            Ok(success) => LoginResponse::Success(Box::new(success)),
            Err(LoginFailure::Message(key)) => rejected(key, lang),
            Err(LoginFailure::Storage) => rejected(MSG_DATABASE_ERROR, lang),
            Err(LoginFailure::Session(error)) => {
                let (status, code) = session_error_code(&error);
                LoginResponse::Session { status, code }
            }
        })
    }

    /// Port of Go `setupLoginAtAuthVersion`：权威重读 → 状态与会话版本 →
    /// 签发会话 → `UpdateUserLastLoginAt` → 审计日志 → SelfUser 所需资料。
    async fn complete(
        &self,
        expected_auth_version: Option<i64>,
        user_id: i64,
        method: &str,
        ip: &str,
        user_agent: &str,
        now: i64,
    ) -> Result<LoginSuccess, LoginFailure> {
        let profile = self
            .profiles
            .by_id(user_id)
            .await
            .map_err(|_| LoginFailure::Storage)?
            .ok_or(LoginFailure::Message(MSG_USER_NOT_FOUND))?;
        // Go 对 nil/非法用户与禁用状态返回同一条封禁文案。
        if profile.status != login::USER_STATUS_ENABLED {
            return Err(LoginFailure::Message(MSG_USER_BANNED));
        }
        // Go `createLoginSession` 先判 `AuthVersion <= 0`（ErrLoginSessionInvalid，
        // 500），再判期望版本不一致（ErrLoginSessionRevoked，401）。
        if profile.auth_version <= 0 {
            return Err(LoginFailure::Session(SessionAuthError::Storage(
                SessionError::LoginSessionInvalid,
            )));
        }
        if expected_auth_version.is_some_and(|version| version != profile.auth_version) {
            return Err(LoginFailure::Session(SessionAuthError::SessionRevoked));
        }
        let bundle = self
            .auth
            .login(
                LoginInput {
                    user_id,
                    expected_auth_version,
                    login_method: method,
                    ip,
                    user_agent,
                },
                now,
            )
            .await
            .map_err(LoginFailure::Session)?;
        update_last_login(&self.db, user_id, now).await;
        let mut params = serde_json::Map::new();
        params.insert("method".to_owned(), Value::String(method.to_owned()));
        record_login_log(
            &self.db,
            profile.id,
            &profile.username,
            &format!("Logged in successfully via {method}"),
            ip,
            "login",
            params,
            login_audit_other(method, user_agent),
            now,
        )
        .await;
        let permissions = self_user_permissions(&self.policy, profile.id, profile.role as i32)
            .await
            .map_err(|_| LoginFailure::Storage)?;
        Ok(LoginSuccess {
            bundle,
            profile,
            permissions,
        })
    }
}

/// Go `twoFALoginFlowPayload`：`{"auth_version":N}`；缺失/非数值 → `None`。
pub fn payload_auth_version(payload: &str) -> Option<i64> {
    let value: Value = serde_json::from_str(payload).ok()?;
    value.get("auth_version")?.as_i64()
}

/// Go `UpdateUserLastLoginAt`：失败仅记日志，不改变登录结果。
pub async fn update_last_login(db: &Database, user_id: i64, now: i64) {
    let sql = "UPDATE users SET last_login_at=$1 WHERE id=$2";
    let result = match db {
        Database::Sqlite(pool) => sqlx::query(sql).bind(now).bind(user_id).execute(pool).await,
        Database::Postgres(pool) => sqlx::query(sql).bind(now).bind(user_id).execute(pool).await,
    };
    if result.is_err() {
        tracing::warn!(
            event = "last_login_update_failed",
            "failed to update user last_login_at"
        );
    }
}

/// Go `recordLoginAudit` + `buildOpField` 的 `other` JSON 形状。
pub fn login_audit_other(method: &str, user_agent: &str) -> serde_json::Map<String, Value> {
    let mut other = serde_json::Map::new();
    other.insert("login_method".to_owned(), Value::String(method.to_owned()));
    other.insert(
        "user_agent".to_owned(),
        Value::String(user_agent.to_owned()),
    );
    let mut params = serde_json::Map::new();
    params.insert("method".to_owned(), Value::String(method.to_owned()));
    let mut op = serde_json::Map::new();
    op.insert("action".to_owned(), Value::String("login".to_owned()));
    op.insert("params".to_owned(), Value::Object(params));
    other.insert("op".to_owned(), Value::Object(op));
    other
}

/// Go `GetSetting().SidebarModules`：空/非法 JSON 都按空字符串处理。
pub fn sidebar_modules(setting: &str) -> String {
    if setting.is_empty() {
        return String::new();
    }
    serde_json::from_str::<Value>(setting)
        .ok()
        .and_then(|value| {
            value
                .get("sidebar_modules")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

/// Go `buildSelfUserData` 的纯组装：调用方提供额度展示设置。
pub fn assemble_self_user(
    profile: UserProfile,
    permissions: Permissions,
    display: QuotaDisplaySettings,
) -> SelfUser {
    let sidebar_modules = sidebar_modules(&profile.setting);
    assemble(SelfUserInput {
        profile,
        permissions,
        display,
        sidebar_modules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_matches_go_shape() {
        assert_eq!(payload_auth_version(r#"{"auth_version":7}"#), Some(7));
        // Go `<= 0` 的拒绝在调用方 filter；解析本身只区分有无数值。
        assert_eq!(payload_auth_version(r#"{"auth_version":0}"#), Some(0));
        assert_eq!(payload_auth_version("{}"), None);
        assert_eq!(payload_auth_version("not-json"), None);
        assert_eq!(payload_auth_version(r#"{"auth_version":"7"}"#), None);
    }

    #[test]
    fn audit_other_matches_build_op_field() {
        let other = login_audit_other("password", "ua/1.0");
        let serialized = serde_json::to_string(&Value::Object(other)).unwrap();
        // Go `buildOpField`：action=login、params.method=登录方式。
        assert!(serialized.contains("\"action\":\"login\""));
        assert!(serialized.contains("\"params\":{\"method\":\"password\"}"));
        assert!(serialized.contains("\"login_method\":\"password\""));
        assert!(serialized.contains("\"user_agent\":\"ua/1.0\""));
    }

    #[test]
    fn sidebar_modules_follows_get_setting() {
        assert_eq!(sidebar_modules(""), "");
        assert_eq!(sidebar_modules("not-json"), "");
        assert_eq!(sidebar_modules(r#"{"sidebar_modules":"a|b"}"#), "a|b");
        // Go 对非字符串值扫描失败按零值处理。
        assert_eq!(sidebar_modules(r#"{"sidebar_modules":true}"#), "");
        assert_eq!(sidebar_modules("{}"), "");
    }

    #[test]
    fn login_session_error_codes_match_go_mapping() {
        assert_eq!(
            session_error_code(&SessionAuthError::Unauthorized),
            (401, "AUTH_UNAUTHORIZED")
        );
        assert_eq!(
            session_error_code(&SessionAuthError::SessionRevoked),
            (401, "AUTH_SESSION_REVOKED")
        );
        assert_eq!(
            session_error_code(&SessionAuthError::Storage(SessionError::ActiveLimit)),
            (409, "AUTH_SESSION_LIMIT")
        );
        assert_eq!(
            session_error_code(&SessionAuthError::Storage(SessionError::IssuanceLimit)),
            (429, "AUTH_SESSION_ISSUANCE_LIMIT")
        );
        assert_eq!(
            session_error_code(&SessionAuthError::Storage(
                SessionError::LoginSessionInvalid,
            )),
            (500, "AUTH_INTERNAL_ERROR")
        );
    }
}
