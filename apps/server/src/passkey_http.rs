//! Passkey 端点的 HTTP 适配（Go `identity/enroll_passkey.go` 的九个 handler）。
//!
//! Go 参考（路由注册 `register_api.go`）：
//! - `GET /api/user/passkey`：UserAuth，无 DisableCache
//! - `DELETE /api/user/passkey`：UserAuth + DisableCache
//! - `POST /api/user/passkey/register/{begin,finish}`：UserAuth + DisableCache
//! - `POST /api/user/passkey/verify/{begin,finish}`：UserAuth + DisableCache
//! - `POST /api/user/passkey/login/{begin,finish}`：匿名 +
//!   CriticalRateLimit + DisableCache + 匿名体上限（本模块 `login_guard`）
//! - `DELETE /api/user/:id/reset_passkey`：AdminAuth，无 DisableCache
//!
//! 所有业务结果都是 HTTP 200 + `{success,message,data}`；Go 用硬编码中文
//! 字面量（不经 i18n）的分支逐字返回，Go 用 `CtxApiError(err)` 回复库/库
//! 错误文本的分支落固定分类文案（不转述 SQL 或库文本）。状态机要点：
//! begin 产生的仪式状态序列化进 `auth_flows.payload`（TTL 5 分钟），
//! finish 按条件更新单次消费；注册/解绑在事务内递增 `users.auth_version`
//! 并轮换当前会话（`AdvanceCurrentSessionToUserVersion`）。

use std::net::SocketAddr;

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Extension, Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use newapi_identity::{
    AuthIdentity,
    audit::{AuditOperator, record_manage_audit_with_params, record_user_security_audit},
    auth_flow::AuthFlowRepository,
    crypto::AuthKeys,
    login::orchestrate::{LoginFailure, LoginResponse, LoginService},
    passkey::credential::{AssertionOutcome, StoredCredential},
    passkey::{
        Ceremony, CeremonyUser, DiscoverableAuthentication, PasskeyAuthentication,
        PasskeyCredentialRepository, PasskeyRegistration, PasskeySettings,
        PasskeySettingsRepository, PasskeyStoreError, SettingsError, build_ceremony,
        format_rfc3339,
    },
    passkey::{
        PURPOSE_PASSKEY_LOGIN, PURPOSE_PASSKEY_REGISTER, PURPOSE_PASSKEY_STEP_UP,
        SCOPE_PASSKEY_DELETE, SCOPE_PASSKEY_REGISTER, TransportFacts, create_session_data_flow,
        is_allowed_proof_scope, pop_session_data_flow,
    },
    two_fa::TwoFaRepository,
    user_auth::CredentialKind,
    users::{SessionAdvance, UserMutationError, UserProfile, UserProfileRepository},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::AppState;
use crate::auth::{AuthCredential, AuthenticatedUser, parse_authorization};
use crate::boundary_mw::{disable_cache_headers, fill_disable_cache_headers};

/// Go 硬编码字面量（不经 i18n，前端按字面量比对/展示）。
const MSG_DISABLED: &str = "管理员未启用 Passkey 登录";
const MSG_SESSION_REQUIRED: &str = "当前认证方式不支持安全验证";
const MSG_FLOW_INCOMPLETE: &str = "Passkey 流程参数不完整";
const MSG_CREDENTIAL_INVALID: &str = "Passkey 凭证格式无效";
const MSG_SESSION_EXPIRED: &str = "Passkey 会话不存在或已过期";
const MSG_NOT_BOUND: &str = "该用户尚未绑定 Passkey";
const MSG_CREDENTIAL_NOT_FOUND: &str = "未找到 Passkey 凭证: Passkey 验证失败，请重试或联系管理员";
const MSG_USER_FETCH_FAILED: &str = "用户信息获取失败";
const MSG_USER_DISABLED: &str = "该用户已被禁用";
const MSG_HANDLE_MISMATCH: &str = "用户句柄与凭证不匹配";
const MSG_INVALID_VERIFY_REQUEST: &str = "无效的 Passkey 验证请求";
const MSG_UNSUPPORTED_SCOPE: &str = "不支持的安全验证范围";
const MSG_LOGIN_ABNORMAL: &str = "Passkey 登录状态异常";
const MSG_INVALID_USER_ID: &str = "无效的用户 ID";
const MSG_NO_PERMISSION: &str = "no permission";
const MSG_REGISTER_SUCCESS: &str = "Passkey 注册成功";
const MSG_DELETE_SUCCESS: &str = "Passkey 已解绑";
const MSG_VERIFY_SUCCESS: &str = "Passkey 验证成功";
const MSG_ADMIN_RESET_SUCCESS: &str = "Passkey 已重置";
/// Go 固定分类替换（`ErrFriendlyPasskeyNotFound` / `CtxApiError` 的库文本）。
const MSG_DATABASE_ERROR: &str = "common.database_error";
const MSG_VERIFY_FAILED: &str = "passkey.verify_failed";
const MSG_UPDATE_FAILED: &str = "passkey.update_failed";
const MSG_USER_NOT_FOUND: &str = "user.not_exists";

const HEADER_SECURITY_PROOF: &str = "x-security-proof";

/// Go `passkeyFinishRequest`。
#[derive(Deserialize)]
struct PasskeyFinishRequest {
    #[serde(default)]
    flow_token: String,
    #[serde(default)]
    credential: Option<Value>,
}

/// Go `passkeyVerifyBeginRequest`。
#[derive(Deserialize)]
struct PasskeyVerifyBeginRequest {
    #[serde(default)]
    scope: String,
}

// ---------------------------------------------------------------------------
// 通用助手
// ---------------------------------------------------------------------------

fn request_language(headers: &HeaderMap) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    crate::request_lang::request_language(accept_language.as_deref())
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    newapi_i18n::translate(
        &request_language(headers),
        key,
        std::iter::empty::<(&str, &str)>(),
    )
}

fn api_message(message: &str) -> Response {
    Json(json!({ "success": false, "message": message })).into_response()
}

fn api_key(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({ "success": false, "message": translate(headers, key) })).into_response()
}

fn api_success(message: &str, data: Value) -> Response {
    Json(json!({ "success": true, "message": message, "data": data })).into_response()
}

fn service_unavailable() -> Response {
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

/// 按请求实时读取并解析 Passkey 设置（Go 的 options 表 `passkey` 行 +
/// ServerAddress 派生）。返回（生效视图，ServerAddress 原值）。
#[allow(clippy::result_large_err)]
async fn resolved_settings(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(PasskeySettings, String), Response> {
    let Some(db) = state.db() else {
        return Err(service_unavailable());
    };
    match PasskeySettingsRepository::new(db).load().await {
        Ok((settings, server_address)) => Ok((settings.resolve(&server_address), server_address)),
        Err(SettingsError::Storage) => Err(api_key(headers, MSG_DATABASE_ERROR)),
    }
}

/// Go `BuildWebAuthn`：错误复现 Go 字面量（含替换值）。
#[allow(clippy::result_large_err)]
fn build_ceremony_or_error(
    effective: &PasskeySettings,
    server_address: &str,
    headers: &HeaderMap,
) -> Result<Ceremony, Response> {
    let facts = transport_facts(headers);
    match build_ceremony(effective, &facts, server_address) {
        Ok(ceremony) => Ok(ceremony),
        Err(error) => Err(api_message(&error.message())),
    }
}

/// 从请求头部提取传输事实（Host + TLS），与 Go `c.Host()`/`c.IsTLS()`
/// 同源；转发头不参与（Go `passkey_webauthn_test.go` 是该边界的契约表）。
/// 本端口终结的传输恒为明文（Go 在 TLS 终结代理后同为 `IsTLS=false`），
/// 生产部署的 https origin 须在 PasskeySettings.Origins 配置，与 Go 在
/// 同一部署形态下的可推导集合一致。
fn transport_facts(headers: &HeaderMap) -> TransportFacts {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    TransportFacts {
        host,
        is_tls: false,
    }
}

/// Go `getAuthenticatedUser`：中间件已校验登录态，这里重读用户资料并按
/// Go 返回 401（禁用）或 200+固定文案（存储故障）。
#[allow(clippy::result_large_err)]
async fn authenticated_user(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
) -> Result<UserProfile, Response> {
    let Some(db) = state.db() else {
        return Err(service_unavailable());
    };
    match UserProfileRepository::new(db)
        .by_id(auth_user.0.user_id)
        .await
    {
        Ok(Some(profile)) if profile.status == 1 => Ok(profile),
        Ok(Some(_)) => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "success": false, "message": MSG_USER_DISABLED })),
        )
            .into_response()),
        Ok(None) => Err(api_key(headers, MSG_USER_NOT_FOUND)),
        Err(error) => {
            tracing::warn!(
                event = "passkey_user_lookup_failed",
                category = crate::database_error_class(&error),
                "passkey user lookup failed"
            );
            Err(api_key(headers, MSG_DATABASE_ERROR))
        }
    }
}

/// Go `authtoken.ReadSessionAuthIdentity`：仅会话型凭据携带可绑定的 sid。
fn session_identity(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    now: i64,
) -> Option<AuthIdentity> {
    if auth_user.0.credential != CredentialKind::DashboardSession {
        return None;
    }
    let credential = parse_authorization(headers).ok()?;
    let token = match credential {
        AuthCredential::Bearer(token) | AuthCredential::Raw(token) => token,
    };
    let identity = state.auth()?.parse_access(&token, now).ok()?;
    (identity.user_id == auth_user.0.user_id).then_some(identity)
}

/// 安全验证门（Go `RequireSecurityProof`）。返回验过的会话身份。
enum ProofFailure {
    Invalid,
    Required,
    Expired,
    ScopeMismatch,
    MethodMismatch,
}

fn proof_failure_response(failure: ProofFailure) -> Response {
    let (code, message) = match failure {
        ProofFailure::Invalid => ("SECURITY_PROOF_INVALID", "安全验证状态无效"),
        ProofFailure::Required => ("SECURITY_PROOF_REQUIRED", "需要安全验证"),
        ProofFailure::Expired => ("SECURITY_PROOF_EXPIRED", "安全验证已过期"),
        ProofFailure::ScopeMismatch => ("SECURITY_PROOF_SCOPE_MISMATCH", "安全验证范围不匹配"),
        ProofFailure::MethodMismatch => ("SECURITY_PROOF_METHOD_MISMATCH", "安全验证方式不匹配"),
    };
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "success": false, "code": code, "message": message })),
    )
        .into_response()
}

#[allow(clippy::result_large_err)]
fn require_security_proof(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    required_scope: &str,
    allowed_methods: &[&str],
    now: i64,
) -> Result<AuthIdentity, Response> {
    let Some(identity) = session_identity(state, auth_user, headers, now) else {
        return Err(proof_failure_response(ProofFailure::Invalid));
    };
    let raw = headers
        .get(HEADER_SECURITY_PROOF)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or_default();
    if raw.is_empty() {
        return Err(proof_failure_response(ProofFailure::Required));
    }
    let Some(keys) = session_keys(state) else {
        return Err(proof_failure_response(ProofFailure::Invalid));
    };
    let methods: Vec<String> = allowed_methods.iter().map(|m| (*m).to_owned()).collect();
    match keys.verify_security_proof(raw, &identity, required_scope, &methods, now) {
        Ok(_) => Ok(identity),
        Err(newapi_identity::AuthError::Expired) => {
            Err(proof_failure_response(ProofFailure::Expired))
        }
        Err(newapi_identity::AuthError::ProofScope) => {
            Err(proof_failure_response(ProofFailure::ScopeMismatch))
        }
        Err(newapi_identity::AuthError::ProofMethod) => {
            Err(proof_failure_response(ProofFailure::MethodMismatch))
        }
        Err(_) => Err(proof_failure_response(ProofFailure::Invalid)),
    }
}

/// Go `requirePasskeyRegistrationVerification`：用户启用 2FA 时要求
/// scope=`passkey.register` 的 2FA 安全验证；未启用直接放行。
#[allow(clippy::result_large_err)]
async fn require_registration_verification(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    now: i64,
) -> Result<(), Response> {
    if two_fa_enabled_result(state, auth_user.0.user_id, headers).await? {
        require_security_proof(
            state,
            auth_user,
            headers,
            SCOPE_PASSKEY_REGISTER,
            &["2fa"],
            now,
        )
        .map(|_| ())
    } else {
        Ok(())
    }
}

/// Go `requirePasskeyDeleteVerification`：启用 2FA 时要求 2FA 证明；否则
/// 必须已绑定 Passkey 并持有 scope=`passkey.delete` 的 passkey 证明。
#[allow(clippy::result_large_err)]
async fn require_delete_verification(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    now: i64,
) -> Result<(), Response> {
    if two_fa_enabled_result(state, auth_user.0.user_id, headers).await? {
        return require_security_proof(
            state,
            auth_user,
            headers,
            SCOPE_PASSKEY_DELETE,
            &["2fa"],
            now,
        )
        .map(|_| ());
    }
    let Some(db) = state.db() else {
        return Err(service_unavailable());
    };
    match PasskeyCredentialRepository::new(db)
        .by_user_id(auth_user.0.user_id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return Err(api_message(MSG_NOT_BOUND)),
        Err(_) => return Err(api_key(headers, MSG_VERIFY_FAILED)),
    }
    require_security_proof(
        state,
        auth_user,
        headers,
        SCOPE_PASSKEY_DELETE,
        &["passkey"],
        now,
    )
    .map(|_| ())
}

/// 读取用户 2FA 是否启用；存储故障落固定分类。
#[allow(clippy::result_large_err)]
async fn two_fa_enabled_result(
    state: &AppState,
    user_id: i64,
    headers: &HeaderMap,
) -> Result<bool, Response> {
    let Some(db) = state.db() else {
        return Err(service_unavailable());
    };
    match TwoFaRepository::new(db).by_user_id(user_id).await {
        Ok(record) => Ok(record.is_some_and(|record| record.is_enabled)),
        Err(_) => {
            // `TwoFaError` 本就是固定分类（不携带数据库文本），类别直接落固定串。
            tracing::warn!(
                event = "passkey_twofa_lookup_failed",
                category = "two_fa_storage",
                "passkey 2FA status lookup failed"
            );
            Err(api_key(headers, MSG_DATABASE_ERROR))
        }
    }
}

/// `AppState::flow_key` 是 `auth-flow-v1:` + SESSION_SECRET，access/proof
/// 签名器从同一 secret 派生（与 twofa_http 同一做法）。
fn session_keys(state: &AppState) -> Option<AuthKeys> {
    let secret = state.flow_key()?.strip_prefix(b"auth-flow-v1:")?;
    std::str::from_utf8(secret).ok().map(AuthKeys::new)
}

/// Go `AdvanceCurrentSessionToUserVersion` + `authRotationData`：推进当前
/// 会话的 auth_version、撤销其他会话、按新版本签发 access token。
#[allow(clippy::result_large_err)]
async fn rotate_session(
    state: &AppState,
    headers: &HeaderMap,
    identity: &AuthIdentity,
    next_user_auth_version: i64,
    now: i64,
) -> Result<Value, Response> {
    let Some(db) = state.db() else {
        return Err(service_unavailable());
    };
    if next_user_auth_version <= identity.user_auth_version {
        return Err(api_key(headers, MSG_DATABASE_ERROR));
    }
    let Some(session_version) = identity.session_version.checked_add(1) else {
        return Err(api_key(headers, MSG_DATABASE_ERROR));
    };
    let projection = match UserProfileRepository::new(db)
        .advance_session_auth_version(SessionAdvance {
            user_id: identity.user_id,
            sid: &identity.sid,
            expected_session_version: identity.session_version,
            expected_user_auth_version: identity.user_auth_version,
            next_user_auth_version,
            now,
        })
        .await
    {
        Ok(projection) => projection,
        Err(error) => {
            if let UserMutationError::Storage(error) = &error {
                tracing::warn!(
                    event = "passkey_session_advance_failed",
                    category = crate::database_error_class(error),
                    "passkey session advance failed"
                );
            }
            return Err(api_key(headers, MSG_DATABASE_ERROR));
        }
    };
    let Some(auth) = state.auth() else {
        return Err(api_key(headers, MSG_DATABASE_ERROR));
    };
    if auth.revoke_others(identity, now).await.is_err() {
        tracing::warn!(
            event = "passkey_session_revoke_failed",
            "passkey other-session revoke failed"
        );
        return Err(api_key(headers, MSG_DATABASE_ERROR));
    }
    let Some(keys) = session_keys(state) else {
        return Err(api_key(headers, MSG_DATABASE_ERROR));
    };
    let new_identity = AuthIdentity {
        user_id: identity.user_id,
        sid: identity.sid.clone(),
        user_auth_version: next_user_auth_version,
        session_version,
    };
    let issued = match keys.issue_access(&new_identity, now) {
        Ok(issued) => issued,
        Err(_) => return Err(api_key(headers, MSG_DATABASE_ERROR)),
    };
    Ok(json!({
        "access_token": issued.token.expose_secret(),
        "token_type": "Bearer",
        "access_expires_at": issued.expires_at,
        "session": {
            "sid": projection.sid,
            "current": true,
            "login_method": projection.login_method,
            "ip": projection.ip,
            "user_agent": projection.user_agent,
            "created_at": projection.created_at,
            "last_active_at": projection.last_active_at,
            "expires_at": projection.expires_at,
        },
    }))
}

/// Go `parsePasskeyFinishRequest`：flow_token 与 credential 任一为空即
/// “参数不完整”；credential 随后按 webauthn 协议结构解析。
#[allow(clippy::result_large_err)]
fn parse_finish_request(body: &Bytes) -> Result<(String, Value), Response> {
    let parsed: PasskeyFinishRequest =
        serde_json::from_slice(body).map_err(|_| api_message(MSG_FLOW_INCOMPLETE))?;
    if parsed.flow_token.trim().is_empty() {
        return Err(api_message(MSG_FLOW_INCOMPLETE));
    }
    let Some(credential) = parsed.credential.filter(|value| !value.is_null()) else {
        return Err(api_message(MSG_FLOW_INCOMPLETE));
    };
    Ok((parsed.flow_token, credential))
}

/// 从注册响应顶层提取 `authenticatorAttachment`（Go
/// `credential.Authenticator.Attachment` 的来源），仅接受 platform/
/// cross-platform，其余视为未提供。
fn attachment_of(credential: &Value) -> Option<String> {
    credential
        .get("authenticatorAttachment")
        .and_then(Value::as_str)
        .filter(|value| *value == "platform" || *value == "cross-platform")
        .map(str::to_owned)
}

/// 注册响应：只提取 attachment；协议结构解析交给 ceremony（复用同一
/// 固定文案），避免 HTTP 层直接依赖 webauthn 类型。
#[allow(clippy::result_large_err)]
fn parse_registration_credential(credential: Value) -> Result<(Value, Option<String>), Response> {
    if !credential.is_object() {
        return Err(api_message(MSG_CREDENTIAL_INVALID));
    }
    let attachment = attachment_of(&credential);
    Ok((credential, attachment))
}

/// 断言响应：仅做对象级校验；rawId/userHandle 的 base64url 解码在
/// login_finish 内完成。
#[allow(clippy::result_large_err)]
fn parse_assertion_credential(credential: Value) -> Result<Value, Response> {
    if !credential.is_object() {
        return Err(api_message(MSG_CREDENTIAL_INVALID));
    }
    Ok(credential)
}

/// 断言的 rawId（base64url）→ 凭据 ID 原始字节。
fn assertion_raw_id(assertion: &Value) -> Vec<u8> {
    assertion["rawId"]
        .as_str()
        .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
        .unwrap_or_default()
}

/// 断言的 userHandle（base64url）→ 原始字节；缺失或解析失败返回 None。
fn assertion_user_handle(assertion: &Value) -> Option<Vec<u8>> {
    assertion["response"]["userHandle"]
        .as_str()
        .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
}

/// 仓储错误 → Go 的 `CtxApiError(err)` 对应分支。
fn store_error_response(headers: &HeaderMap, error: PasskeyStoreError) -> Response {
    match error {
        PasskeyStoreError::NotFound => api_key(headers, MSG_UPDATE_FAILED),
        PasskeyStoreError::Storage => api_key(headers, MSG_DATABASE_ERROR),
    }
}

fn user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

/// 已存凭据的排除列表（Go `WithExclusions`）：按 credential_id 列的
/// base64 还原字节，不做 COSE 重建。
fn exclusion_credential_ids(
    existing: &newapi_identity::passkey::credential::PasskeyCredential,
) -> Vec<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(&existing.credential_id)
        .map(|bytes| vec![bytes])
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 用户自管理
// ---------------------------------------------------------------------------

/// Go `PasskeyStatus`：纯 `UserAuth`，无缓存头。
pub async fn status(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return service_unavailable();
    };
    let user = match authenticated_user(&state, &auth_user, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match PasskeyCredentialRepository::new(db)
        .by_user_id(user.id)
        .await
    {
        Ok(None) => api_success("", json!({ "enabled": false })),
        Ok(Some(credential)) => api_success(
            "",
            json!({
                "enabled": true,
                "last_used_at": credential.last_used_at.map(format_rfc3339),
            }),
        ),
        Err(_) => api_key(&headers, MSG_VERIFY_FAILED),
    }
}

/// Go `PasskeyRegisterBegin`。
pub async fn register_begin(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let now = crate::http::now_seconds();
    let mut response = register_begin_inner(&state, &auth_user, &headers, now).await;
    disable_cache_headers(&mut response);
    response
}

async fn register_begin_inner(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    now: i64,
) -> Response {
    let (effective, server_address) = match resolved_settings(state, headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !effective.enabled {
        return api_message(MSG_DISABLED);
    }
    let user = match authenticated_user(state, auth_user, headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = require_registration_verification(state, auth_user, headers, now).await {
        return response;
    }
    let Some(db) = state.db() else {
        return service_unavailable();
    };
    let repository = PasskeyCredentialRepository::new(db.clone());
    let exclude = match repository.by_user_id(user.id).await {
        Ok(Some(existing)) => exclusion_credential_ids(&existing),
        Ok(None) => Vec::new(),
        Err(_) => return api_key(headers, MSG_VERIFY_FAILED),
    };
    let ceremony = match build_ceremony_or_error(&effective, &server_address, headers) {
        Ok(ceremony) => ceremony,
        Err(response) => return response,
    };
    let ceremony_user = CeremonyUser {
        id: user.id,
        username: &user.username,
        display_name: &user.display_name,
    };
    let (options, registration) = match ceremony.begin_registration(&ceremony_user, exclude) {
        Ok(value) => value,
        Err(_) => return api_key(headers, MSG_VERIFY_FAILED),
    };
    // Go 在 BeginRegistration 之后才读会话身份（CreateSessionDataFlow 需要
    // sessionID）；保持同一顺序。
    let Some(identity) = session_identity(state, auth_user, headers, now) else {
        return api_message(MSG_SESSION_REQUIRED);
    };
    let flow = match auth_flow(state, &db) {
        Some(flow) => flow,
        None => return service_unavailable(),
    };
    let state_value = match serde_json::to_value(&registration) {
        Ok(value) => value,
        Err(_) => return api_key(headers, MSG_VERIFY_FAILED),
    };
    let (token, expires_at) = match create_session_data_flow(
        &flow,
        PURPOSE_PASSKEY_REGISTER,
        user.id,
        &identity.sid,
        SCOPE_PASSKEY_REGISTER,
        &state_value,
        now,
    )
    .await
    {
        Ok(value) => value,
        Err(_) => return api_key(headers, MSG_DATABASE_ERROR),
    };
    api_success(
        "",
        json!({
            "options": options,
            "flow_token": token.expose_secret(),
            "expires_at": expires_at,
        }),
    )
}

/// Go `PasskeyRegisterFinish`。
pub async fn register_finish(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = crate::http::now_seconds();
    let mut response = register_finish_inner(&state, &auth_user, &headers, &body, now).await;
    disable_cache_headers(&mut response);
    response
}

async fn register_finish_inner(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    body: &Bytes,
    now: i64,
) -> Response {
    let (effective, server_address) = match resolved_settings(state, headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !effective.enabled {
        return api_message(MSG_DISABLED);
    }
    let user = match authenticated_user(state, auth_user, headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = require_registration_verification(state, auth_user, headers, now).await {
        return response;
    }
    let (flow_token, credential) = match parse_finish_request(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let (registration_credential, attachment) = match parse_registration_credential(credential) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let ceremony = match build_ceremony_or_error(&effective, &server_address, headers) {
        Ok(ceremony) => ceremony,
        Err(response) => return response,
    };
    let Some(identity) = session_identity(state, auth_user, headers, now) else {
        return api_message(MSG_SESSION_REQUIRED);
    };
    let Some(db) = state.db() else {
        return service_unavailable();
    };
    let flow = match auth_flow(state, &db) {
        Some(flow) => flow,
        None => return service_unavailable(),
    };
    let (state_value, _scope) = match pop_session_data_flow(
        &flow,
        &flow_token,
        PURPOSE_PASSKEY_REGISTER,
        user.id,
        &identity.sid,
        now,
    )
    .await
    {
        Ok(value) => value,
        Err(_) => return api_message(MSG_SESSION_EXPIRED),
    };
    let registration: PasskeyRegistration = match serde_json::from_value(state_value) {
        Ok(registration) => registration,
        Err(_) => return api_message(MSG_SESSION_EXPIRED),
    };
    let registered = match ceremony.finish_registration(registration_credential, &registration) {
        Ok(registered) => registered,
        Err(_) => return api_key(headers, MSG_VERIFY_FAILED),
    };
    let stored = StoredCredential {
        credential_id: registered.credential_id,
        public_key: registered.public_key,
        attestation_format: registered.attestation_format,
        counter: registered.counter,
        user_verified: registered.user_verified,
        backup_eligible: registered.backup_eligible,
        backup_state: registered.backup_state,
        transports: registered.transports,
        attachment,
    };
    let repository = PasskeyCredentialRepository::new(db.clone());
    let next_version = match repository
        .upsert_with_auth_version(user.id, &stored, now)
        .await
    {
        Ok(version) => version,
        Err(error) => return store_error_response(headers, error),
    };
    let data = match rotate_session(state, headers, &identity, next_version, now).await {
        Ok(data) => data,
        Err(response) => return response,
    };
    record_user_security_audit(
        &db,
        user.id,
        &user.username,
        "user.passkey_register",
        &crate::http::request_ip(state, headers, None),
        now,
    )
    .await;
    api_success(MSG_REGISTER_SUCCESS, data)
}

/// Go `PasskeyDelete`。
pub async fn delete(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
) -> Response {
    let now = crate::http::now_seconds();
    let mut response = delete_inner(&state, &auth_user, &headers, now).await;
    disable_cache_headers(&mut response);
    response
}

async fn delete_inner(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    now: i64,
) -> Response {
    let user = match authenticated_user(state, auth_user, headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if let Err(response) = require_delete_verification(state, auth_user, headers, now).await {
        return response;
    }
    let Some(identity) = session_identity(state, auth_user, headers, now) else {
        return api_message(MSG_SESSION_REQUIRED);
    };
    let Some(db) = state.db() else {
        return service_unavailable();
    };
    let next_version = match PasskeyCredentialRepository::new(db.clone())
        .delete_with_auth_version(user.id)
        .await
    {
        Ok(version) => version,
        Err(error) => return store_error_response(headers, error),
    };
    let data = match rotate_session(state, headers, &identity, next_version, now).await {
        Ok(data) => data,
        Err(response) => return response,
    };
    record_user_security_audit(
        &db,
        user.id,
        &user.username,
        "user.passkey_delete",
        &crate::http::request_ip(state, headers, None),
        now,
    )
    .await;
    api_success(MSG_DELETE_SUCCESS, data)
}

// ---------------------------------------------------------------------------
// 匿名可发现登录
// ---------------------------------------------------------------------------

/// 登录路由的中间件链（Go 顺序 CriticalRateLimit → DisableCache →
/// AnonymousRequestBodyLimit → handler）：429 不带缓存头，413 与
/// handler 响应都补 no-store。
pub async fn login_guard(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let ip = crate::http::request_ip(&state, request.headers(), peer);
    let now = crate::http::now_seconds();
    match state.check_rate_limit("CT", &ip, now).await {
        Ok(None) => {}
        Ok(Some(retry_after)) => {
            let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
            if retry_after > 0
                && let Ok(value) = axum::http::HeaderValue::from_str(&retry_after.to_string())
            {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            return response;
        }
        // Go 的 Redis 故障分支：500 + Abort，位于 DisableCache 之前。
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    request
        .extensions_mut()
        .insert(crate::login_http::ClientIp(ip));
    let mut response =
        match crate::login_http::read_limited_body(state.anonymous_body_limit(), request).await {
            Err(status) => status.into_response(),
            Ok(request) => next.run(request).await,
        };
    fill_disable_cache_headers(&mut response);
    response
}

/// Go `PasskeyLoginBegin`：匿名端点。
pub async fn login_begin(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let (effective, server_address) = match resolved_settings(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !effective.enabled {
        return api_message(MSG_DISABLED);
    }
    let ceremony = match build_ceremony_or_error(&effective, &server_address, &headers) {
        Ok(ceremony) => ceremony,
        Err(response) => return response,
    };
    let (options, authentication) = match ceremony.begin_login_discoverable() {
        Ok(value) => value,
        Err(_) => return api_key(&headers, MSG_VERIFY_FAILED),
    };
    let Some(db) = state.db() else {
        return service_unavailable();
    };
    let flow = match auth_flow(&state, &db) {
        Some(flow) => flow,
        None => return service_unavailable(),
    };
    let state_value = match serde_json::to_value(&authentication) {
        Ok(value) => value,
        Err(_) => return api_key(&headers, MSG_VERIFY_FAILED),
    };
    let (token, expires_at) = match create_session_data_flow(
        &flow,
        PURPOSE_PASSKEY_LOGIN,
        0,
        "",
        "",
        &state_value,
        crate::http::now_seconds(),
    )
    .await
    {
        Ok(value) => value,
        Err(_) => return api_key(&headers, MSG_DATABASE_ERROR),
    };
    api_success(
        "",
        json!({
            "options": options,
            "flow_token": token.expose_secret(),
            "expires_at": expires_at,
        }),
    )
}

/// Go `PasskeyLoginFinish`：匿名端点，可发现凭据在 finish 时定位用户。
pub async fn login_finish(
    State(state): State<AppState>,
    Extension(crate::login_http::ClientIp(ip)): Extension<crate::login_http::ClientIp>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = crate::http::now_seconds();
    let (effective, server_address) = match resolved_settings(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !effective.enabled {
        return api_message(MSG_DISABLED);
    }
    let (flow_token, credential) = match parse_finish_request(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let assertion = match parse_assertion_credential(credential) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let ceremony = match build_ceremony_or_error(&effective, &server_address, &headers) {
        Ok(ceremony) => ceremony,
        Err(response) => return response,
    };
    let Some(db) = state.db() else {
        return service_unavailable();
    };
    let flow = match auth_flow(&state, &db) {
        Some(flow) => flow,
        None => return service_unavailable(),
    };
    let (state_value, _scope) =
        match pop_session_data_flow(&flow, &flow_token, PURPOSE_PASSKEY_LOGIN, 0, "", now).await {
            Ok(value) => value,
            Err(_) => return api_message(MSG_SESSION_EXPIRED),
        };
    let authentication: DiscoverableAuthentication = match serde_json::from_value(state_value) {
        Ok(authentication) => authentication,
        Err(_) => return api_message(MSG_SESSION_EXPIRED),
    };
    // Go handler 回调：按 credential ID 查凭据与用户，校验状态与 userHandle。
    let repository = PasskeyCredentialRepository::new(db.clone());
    let stored = match repository
        .by_credential_id(&assertion_raw_id(&assertion))
        .await
    {
        Ok(Some(stored)) => stored,
        Ok(None) | Err(_) => return api_message(MSG_CREDENTIAL_NOT_FOUND),
    };
    let user = match UserProfileRepository::new(db.clone())
        .by_id(stored.user_id)
        .await
    {
        Ok(Some(user)) => user,
        Ok(None) | Err(_) => return api_message(MSG_USER_FETCH_FAILED),
    };
    if user.status != 1 {
        return api_message(MSG_USER_DISABLED);
    }
    if let Some(user_handle) = assertion_user_handle(&assertion)
        && !user_handle.is_empty()
    {
        match newapi_identity::passkey::ceremony::user_handle_to_user_id(&user_handle) {
            Some(handle_id) if handle_id != user.id => {
                return api_message(MSG_HANDLE_MISMATCH);
            }
            // 长度/编码不符：Go 只记日志并继续验证（strconv.Atoi 失败分支）。
            _ => tracing::warn!(
                event = "passkey_login_user_handle_unparsed",
                len = user_handle.len(),
                "passkey login userHandle is not the expected encoding"
            ),
        }
    }
    let credential = match stored.to_webauthn_credential() {
        Ok(credential) => credential,
        Err(_) => return api_message(MSG_LOGIN_ABNORMAL),
    };
    let result = match ceremony.finish_login_discoverable(&assertion, authentication, &credential) {
        Ok(result) => result,
        Err(_) => return api_key(&headers, MSG_VERIFY_FAILED),
    };
    if let Err(error) = repository
        .update_assertion_state(
            user.id,
            result.cred_id(),
            &AssertionOutcome {
                counter: result.counter(),
                user_verified: result.user_verified(),
                backup_eligible: result.backup_eligible(),
                backup_state: result.backup_state(),
            },
            now,
        )
        .await
    {
        return store_error_response(&headers, error);
    }
    let Some(login) = login_service(&state) else {
        return service_unavailable();
    };
    // Go `SetupLogin`：不校验 expected auth_version（0 分支）。
    let outcome = login
        .complete_session(user.id, "passkey", &ip, &user_agent(&headers), now)
        .await;
    match outcome {
        Ok(success) => crate::login_http::render(
            &state,
            Ok(LoginResponse::Success(Box::new(success))),
            &headers,
        ),
        // Go 的 `setupLoginAtAuthVersion` 失败走 `writeAuthSessionError`
        // （401/409/500 + code）或 `CtxApiError`（200 文案）；复用登录侧定型。
        Err(LoginFailure::Storage) => api_key(&headers, MSG_DATABASE_ERROR),
        Err(LoginFailure::Message(key)) => api_key(&headers, key),
        Err(LoginFailure::Session(error)) => {
            let (status, code) = newapi_identity::login::orchestrate::session_error_code(&error);
            session_error(status, code)
        }
    }
}

// ---------------------------------------------------------------------------
// 登录后二次验证（Go verify 流）
// ---------------------------------------------------------------------------

/// Go `PasskeyVerifyBegin`。
pub async fn verify_begin(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = crate::http::now_seconds();
    let mut response = verify_begin_inner(&state, &auth_user, &headers, &body, now).await;
    disable_cache_headers(&mut response);
    response
}

async fn verify_begin_inner(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    body: &Bytes,
    now: i64,
) -> Response {
    let (effective, server_address) = match resolved_settings(state, headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !effective.enabled {
        return api_message(MSG_DISABLED);
    }
    let user = match authenticated_user(state, auth_user, headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let request: PasskeyVerifyBeginRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(_) => return api_message(MSG_INVALID_VERIFY_REQUEST),
    };
    if !is_allowed_proof_scope(&request.scope) {
        return api_message(MSG_UNSUPPORTED_SCOPE);
    }
    let Some(db) = state.db() else {
        return service_unavailable();
    };
    let repository = PasskeyCredentialRepository::new(db.clone());
    // Go：GetPasskeyByUserID 的任意错误（含未绑定）都回“尚未绑定”。
    let existing = match repository.by_user_id(user.id).await {
        Ok(Some(existing)) => existing,
        Ok(None) | Err(_) => return api_message(MSG_NOT_BOUND),
    };
    let ceremony = match build_ceremony_or_error(&effective, &server_address, headers) {
        Ok(ceremony) => ceremony,
        Err(response) => return response,
    };
    let credential = match existing.to_webauthn_credential() {
        Ok(credential) => credential,
        Err(_) => return api_message(MSG_NOT_BOUND),
    };
    let (options, authentication) = match ceremony.begin_verification(&credential) {
        Ok(value) => value,
        Err(_) => return api_key(headers, MSG_VERIFY_FAILED),
    };
    let Some(identity) = session_identity(state, auth_user, headers, now) else {
        return api_message(MSG_SESSION_REQUIRED);
    };
    let flow = match auth_flow(state, &db) {
        Some(flow) => flow,
        None => return service_unavailable(),
    };
    let state_value = match serde_json::to_value(&authentication) {
        Ok(value) => value,
        Err(_) => return api_key(headers, MSG_VERIFY_FAILED),
    };
    let (token, expires_at) = match create_session_data_flow(
        &flow,
        PURPOSE_PASSKEY_STEP_UP,
        user.id,
        &identity.sid,
        &request.scope,
        &state_value,
        now,
    )
    .await
    {
        Ok(value) => value,
        Err(_) => return api_key(headers, MSG_DATABASE_ERROR),
    };
    api_success(
        "",
        json!({
            "options": options,
            "flow_token": token.expose_secret(),
            "expires_at": expires_at,
        }),
    )
}

/// Go `PasskeyVerifyFinish`。
pub async fn verify_finish(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let now = crate::http::now_seconds();
    let mut response = verify_finish_inner(&state, &auth_user, &headers, &body, now).await;
    disable_cache_headers(&mut response);
    response
}

async fn verify_finish_inner(
    state: &AppState,
    auth_user: &AuthenticatedUser,
    headers: &HeaderMap,
    body: &Bytes,
    now: i64,
) -> Response {
    let (effective, server_address) = match resolved_settings(state, headers).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !effective.enabled {
        return api_message(MSG_DISABLED);
    }
    let user = match authenticated_user(state, auth_user, headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let (flow_token, credential) = match parse_finish_request(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let assertion = match parse_assertion_credential(credential) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let Some(db) = state.db() else {
        return service_unavailable();
    };
    let repository = PasskeyCredentialRepository::new(db.clone());
    let existing = match repository.by_user_id(user.id).await {
        Ok(Some(existing)) => existing,
        Ok(None) | Err(_) => return api_message(MSG_NOT_BOUND),
    };
    let ceremony = match build_ceremony_or_error(&effective, &server_address, headers) {
        Ok(ceremony) => ceremony,
        Err(response) => return response,
    };
    let Some(identity) = session_identity(state, auth_user, headers, now) else {
        return api_message(MSG_SESSION_REQUIRED);
    };
    let flow = match auth_flow(state, &db) {
        Some(flow) => flow,
        None => return service_unavailable(),
    };
    let (state_value, scope) = match pop_session_data_flow(
        &flow,
        &flow_token,
        PURPOSE_PASSKEY_STEP_UP,
        user.id,
        &identity.sid,
        now,
    )
    .await
    {
        Ok(value) => value,
        Err(_) => return api_message(MSG_SESSION_EXPIRED),
    };
    let authentication: PasskeyAuthentication = match serde_json::from_value(state_value) {
        Ok(authentication) => authentication,
        Err(_) => return api_message(MSG_SESSION_EXPIRED),
    };
    // Go `ValidateLogin` 的前置：确认存储凭据可重建为校验用凭据；重建产物本身
    // 不参与断言（允许列表已随状态持久化）。
    if existing.to_webauthn_credential().is_err() {
        return api_message(MSG_NOT_BOUND);
    }
    let result = match ceremony.finish_verification(&assertion, &authentication) {
        Ok(result) => result,
        Err(_) => return api_key(headers, MSG_VERIFY_FAILED),
    };
    if let Err(error) = repository
        .update_assertion_state(
            user.id,
            result.cred_id(),
            &AssertionOutcome {
                counter: result.counter(),
                user_verified: result.user_verified(),
                backup_eligible: result.backup_eligible(),
                backup_state: result.backup_state(),
            },
            now,
        )
        .await
    {
        return store_error_response(headers, error);
    }
    let Some(keys) = session_keys(state) else {
        return service_unavailable();
    };
    let scopes = vec![scope.clone()];
    match keys.issue_security_proof(&identity, "passkey", &scopes, now) {
        Ok(proof) => api_success(
            MSG_VERIFY_SUCCESS,
            json!({
                "proof_token": proof.token.expose_secret(),
                "expires_at": proof.expires_at,
                "method": "passkey",
                "scope": scope,
            }),
        ),
        Err(_) => api_key(headers, MSG_DATABASE_ERROR),
    }
}

// ---------------------------------------------------------------------------
// 管理员重置
// ---------------------------------------------------------------------------

/// Go `AdminResetPasskey`：纯 `AdminAuth`，无 DisableCache、无限流。
pub async fn admin_reset(
    State(state): State<AppState>,
    Extension(admin_user): Extension<AuthenticatedUser>,
    Path(user_id): Path<String>,
    request: Request,
) -> Response {
    let (parts, _body) = request.into_parts();
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let headers = parts.headers;
    let client_ip = crate::http::request_ip(&state, &headers, peer);
    let now = crate::http::now_seconds();

    let Ok(user_id) = user_id.parse::<i64>() else {
        return api_message(MSG_INVALID_USER_ID);
    };
    let Some(db) = state.db() else {
        return service_unavailable();
    };
    let target = match UserProfileRepository::new(db.clone()).by_id(user_id).await {
        Ok(Some(target)) => target,
        Ok(None) => return api_key(&headers, MSG_USER_NOT_FOUND),
        Err(error) => {
            tracing::warn!(
                event = "admin_passkey_user_lookup_failed",
                category = crate::database_error_class(&error),
                "admin passkey target lookup failed"
            );
            return api_key(&headers, MSG_DATABASE_ERROR);
        }
    };
    if !newapi_identity::two_fa::can_manage_target_role(admin_user.0.role, target.role) {
        return api_message(MSG_NO_PERMISSION);
    }
    let repository = PasskeyCredentialRepository::new(db.clone());
    match repository.by_user_id(target.id).await {
        Ok(Some(_)) => {}
        Ok(None) => return api_message(MSG_NOT_BOUND),
        Err(_) => return api_key(&headers, MSG_VERIFY_FAILED),
    }
    if let Err(error) = repository.delete_with_auth_version(target.id).await {
        return store_error_response(&headers, error);
    }
    // Go 在删除事务提交后调用 `RevokeAllUserSessions(userId,
    // "admin_passkey_reset")`（enroll_passkey.go:473-476）：把该用户全部活跃
    // 会话行立即置 revoked（RevokedAt/RevokedReason 落库），会话列表随即不再
    // 显示它们；auth_version 已在上一个事务内递增，旧令牌同样被版本检查拒绝。
    // 事务边界与 Go 对齐：撤销是独立批次事务，不含在 passkey 删除事务内。
    let Some(auth) = state.auth() else {
        return service_unavailable();
    };
    if let Err(error) = auth.revoke_all(target.id, "admin_passkey_reset", now).await {
        tracing::warn!(
            event = "admin_passkey_session_revoke_failed",
            error = ?error,
            "admin passkey session revoke failed"
        );
        return api_key(&headers, MSG_DATABASE_ERROR);
    }
    let auth_method = match admin_user.0.credential {
        CredentialKind::DashboardSession => "session",
        CredentialKind::PersonalAccessToken => "access_token",
    };
    let mut params = Map::new();
    params.insert("id".to_owned(), json!(target.id));
    params.insert("username".to_owned(), json!(target.username));
    record_manage_audit_with_params(
        &db,
        &AuditOperator {
            user_id: admin_user.0.user_id,
            username: &admin_user.0.username,
            role: admin_user.0.role,
            auth_method,
        },
        "user.reset_passkey",
        target.id,
        Some(&params),
        &client_ip,
        now,
    )
    .await;
    // Go 成功响应只含 success/message，无 data 键。
    Json(json!({ "success": true, "message": MSG_ADMIN_RESET_SUCCESS })).into_response()
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

fn auth_flow(state: &AppState, db: &newapi_storage::Database) -> Option<AuthFlowRepository> {
    let flow_key = state.flow_key()?;
    Some(AuthFlowRepository::new(db.clone(), flow_key.to_vec()))
}

fn login_service(state: &AppState) -> Option<LoginService> {
    let auth = state.auth_arc()?;
    let db = state.db()?;
    let flow_key = state.flow_key()?.to_vec();
    Some(LoginService::new(auth, db, flow_key))
}

fn session_error(status: u16, code: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (
        status,
        Json(json!({
            "success": false,
            "code": code,
            "message": status.canonical_reason().unwrap_or("error"),
        })),
    )
        .into_response();
    disable_cache_headers(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finish_request_requires_flow_token_and_credential() {
        assert!(parse_finish_request(&Bytes::from_static(br#"{"flow_token":""}"#)).is_err());
        assert!(parse_finish_request(&Bytes::from_static(br#"{"flow_token":"t"}"#)).is_err());
        let (token, credential) = parse_finish_request(&Bytes::from_static(
            br#"{"flow_token":"t","credential":{"id":"x"}}"#,
        ))
        .expect("both fields parse");
        assert_eq!(token, "t");
        assert_eq!(credential["id"], "x");
    }

    #[test]
    fn attachment_only_accepts_known_values() {
        assert_eq!(
            attachment_of(&json!({"authenticatorAttachment": "platform"})),
            Some("platform".to_owned())
        );
        assert_eq!(
            attachment_of(&json!({"authenticatorAttachment": "cross-platform"})),
            Some("cross-platform".to_owned())
        );
        assert_eq!(
            attachment_of(&json!({"authenticatorAttachment": "phone"})),
            None
        );
        assert_eq!(attachment_of(&json!({})), None);
    }

    #[test]
    fn user_handle_roundtrips_user_id() {
        // 注册期写入 u128 大端（高 8 字节零填充）。
        let mut handle = [0u8; 16];
        handle[8..16].copy_from_slice(&7_i64.to_be_bytes());
        assert_eq!(
            newapi_identity::passkey::ceremony::user_handle_to_user_id(&handle),
            Some(7)
        );
        assert_eq!(
            newapi_identity::passkey::ceremony::user_handle_to_user_id(&[1, 2, 3]),
            None
        );
    }
}
